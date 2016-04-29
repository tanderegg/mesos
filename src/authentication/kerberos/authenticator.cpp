// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>   // For size_t needed by sasl.h

#include <sasl/sasl.h>
#include <sasl/saslplug.h>

#include <map>
#include <vector>

#include <mesos/mesos.hpp>

#include <process/defer.hpp>
#include <process/once.hpp>
#include <process/owned.hpp>
#include <process/protobuf.hpp>

#include <stout/check.hpp>
#include <stout/hashmap.hpp>
#include <stout/lambda.hpp>

#include "authenticator.hpp"
#include "messages/messages.hpp"

// We need to disable the deprecation warnings as Apple has decided
// to deprecate all of CyrusSASL's functions with OS 10.11
// (see MESOS-3030). We are using GCC pragmas also for covering clang.
#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace mesos {
namespace internal {
namespace kerberos {

using namespace process;
using std::string;

class KerberosAuthenticatorSessionProcess :
  public ProtobufProcess<KerberosAuthenticatorSessionProcess>
{
public:
  explicit KerberosAuthenticatorSessionProcess(const UPID& _pid)
    : ProcessBase(ID::generate("kerberos_authenticator_session")),
      status(READY),
      pid(_pid),
      connection(NULL) {}

  virtual ~KerberosAuthenticatorSessionProcess()
  {
    if (connection != NULL) {
      sasl_dispose(&connection);
    }
  }

  virtual void finalize()
  {
    discarded(); // Fail the promise
  }

  Future<Option<string>> authenticate()
  {
    if (status != READY) {
      return promise.future();
    }

    callbacks[0].id = SASL_CB_GETOPT;
    callbacks[0].proc = (int(*)()) &getopt;
    callbacks[0].context = NULL;

    callbacks[1].id = SASL_CB_CANON_USER;
    callbacks[1].proc = (int(*)()) &cannonicalize;
    // Pass in the principal so we can set it in cannon_user().
    callbacks[1].context = &principal;

    callbacks[2].id = SASL_CB_LIST_END;
    callbacks[2].proc = NULL;
    callbacks[2].context = NULL;

    LOG(INFO) << "Creating new server SASL connection";

    int result = sasl_server_new(
        "mesos",    // Registered name of service.
        NULL,       // Server's FQDN; NULL users gethostname().
        NULL,       // The user realm used for password lookups;
                    // NULL means default to FQDN.
                    // NOTE: This does not affect Kerberos
        NULL, NULL, // IP address information strings.
        callbacks,  // Callbacks supported only for this connection.
        0,          // Security flags (security layers are enabled
                    // using security properties, separately).
        &connection);

      if (result != SASL_OK) {
        string error = "Failed to create server SASL connection: ";
        error += sasl_errstring(result, NULL, NULL);
        LOG(ERROR) << error;
        AuthenticationErrorMessage message;
        message.set_error(error);
        send(pid, message);
        status = ERROR;
        promise.fail(error);
        return promise.future();
      }

      // Get the list of mechanisms
      const char* output = NULL;
      unsigned length = 0;
      int count = 0;

      result = sasl_listmech(
        connection,  // The context for this connection.
        NULL,        // Not supported.
        "",          // What to prepend to the output string.
        ",",         // What to separate mechanisms with.
        "",          // What to append to the output string.
        &output,     // The output string.
        &length,     // The length of the output string.
        &count);     // The count of the mechanisms in output.

      if (result != SASL_OK) {
        string error = "Failed to get list of mechanisms: ";
        LOG(WARNING) << error << sasl_errstring(result, NULL, NULL);
        AuthenticationErrorMessage message;
        error += sasl_errdetail(connection);
        message.set_error(error);
        send(pid, message);
        status = ERROR;
        promise.fail(error);
        return promise.future();
      }

      std::vector<string> mechanisms = strings::tokenize(output, ",");

      // Send authentication mechanisms.
      AuthenticationMechanismsMessage message;
      foreach (const string& mechanism, mechanisms) {
        VLOG(1) << "Adding SASL mechanism: " << mechanism;
        message.add_mechanisms(mechanism);
      }

      send(pid, message);

      status = STARTING;

      // Stop authenticating if nobody cares.
      promise.future().onDiscard(defer(self(), &Self::discarded));

      return promise.future();
  }

  virtual void initialze()
  {
    link(pid); // Don't bother waiting for a lost authenticatee.

    // Anticipate start and steps messages from the client.
    install<AuthenticationStartMessage>(
      &KerberosAuthenticatorSessionProcess::start,
      &AuthenticationStartMessage::mechanism,
      &AuthenticationStartMessage::data);

    install<AuthenticationStepMessage>(
      &KerberosAuthenticatorSessionProcess::step,
      &AuthenticationStepMessage::data);
  }

  virtual void exited(const UPID& _pid)
  {
    if (pid == _pid) {
      status = ERROR;
      promise.fail("Failed to communicate with authenticatee");
    }
  }

  void start(const string& mechanism, const string& data)
  {
    if (status != STARTING) {
      AuthenticationErrorMessage message;
      message.set_error("Unexpected authentication 'start' received");
      send(pid, message);
      status = ERROR;
      promise.fail(message.error());
      return;
    }

    LOG(INFO) << "Received SASL authentication start";

    // Start the server.
    const char* output = NULL;
    unsigned length = 0;

    int result = sasl_server_start(
      connection,
      mechanism.c_str(),
      data.length() == 0 ? NULL : data.data(),
      data.length(),
      &output,
      &length);

    handle(result, output, length);
  }

  void step(const string& data)
  {
    if (status != STEPPING) {
      AuthenticationErrorMessage message;
      message.set_error("Unexpected authentication 'step' received");
      send(pid, message);
      status = ERROR;
      promise.fail(message.error());
      return;
    }

    LOG(INFO) << "Received SASL authentication step";

    const char* output = NULL;
    unsigned length = 0;

    int result = sasl_server_step(
      connection,
      data.length() == 0 ? NULL : data.data(),
      data.length(),
      &output,
      &length);

    handle(result, output, length);
  }

  void discarded()
  {
    status = DISCARDED;
    promise.fail("Authentication discarded");
  }

private:
  static int getopt(
      void *context,
      const char* plugin,
      const char* option,
      const char** result,
      unsigned* length)
  {
    bool found = false;
    if (string(option) == "mech_list") {
      *result = "GSSAPI";
      found = true;
    }

    if (found && length != NULL) {
      *length = strlen(*result);
    }

    return SASL_OK;
  }

  // Callback for cannonicalizing the username(principal). We use it
  // to record the principal in KerberosAuthenticator.
  static int cannonicalize(
    sasl_conn_t* connection,
    void* context,
    const char* input,
    unsigned inputLength,
    unsigned flags,
    const char* userRealm,
    char* output,
    unsigned outputMaxLength,
    unsigned* outputLength)
  {
    CHECK_NOTNULL(input);
    CHECK_NOTNULL(context);
    CHECK_NOTNULL(output);

    // Save the input
    Option<string>* principal =
      static_cast<Option<string>*>(context);
    CHECK(principal->isNone());
    *principal = string(input, inputLength);

    // Tell SASL that the canonical username is the same as the
    // client-supplied username.
    memcpy(output, input, inputLength);
    *outputLength = inputLength;

    return SASL_OK;
  }

  // Helper for handling result of server start and step.
  void handle(int result, const char* output, unsigned length)
  {
    if (result == SASL_OK) {
      // Principal must have been set if authentication succeeded
      CHECK_SOME(principal);

      LOG(INFO) << "Authentication success";
      // Note that we're not using SASL_SUCCESS_DATA which means that
      // we should not have any data to send when we get a SASL_OK.
      CHECK(output == NULL);
      send(pid, AuthenticationCompletedMessage());
      status = COMPLETED;
      promise.set(principal);
    } else if (result == SASL_CONTINUE) {
      LOG(INFO) << "Authentication requires more steps";
      AuthenticationStepMessage message;
      message.set_data(CHECK_NOTNULL(output), length);
      send(pid, message);
      status = STEPPING;
    } else if (result == SASL_NOUSER || result == SASL_BADAUTH) {
      LOG(WARNING) << "Authentication failure: "
                   << sasl_errstring(result, NULL, NULL);
      send(pid, AuthenticationFailedMessage());
      status = FAILED;
      promise.set(Option<string>::none());
    } else {
      LOG(ERROR) << "Authentication error: "
                 << sasl_errstring(result, NULL, NULL);
      AuthenticationErrorMessage message;
      string error(sasl_errdetail(connection));
      message.set_error(error);
      send(pid, message);
      status = ERROR;
      promise.fail(message.error());
    }
  }

  enum
  {
    READY,
    STARTING,
    STEPPING,
    COMPLETED,
    FAILED,
    ERROR,
    DISCARDED
  } status;

  sasl_callback_t callbacks[3];

  const UPID pid;

  sasl_conn_t* connection;

  Promise<Option<string>> promise;

  Option<string> principal;
};

class KerberosAuthenticatorSession
{
public:
  explicit KerberosAuthenticatorSession(const UPID& pid)
  {
    process = new KerberosAuthenticatorSessionProcess(pid);
    spawn(process);
  }

  virtual ~KerberosAuthenticatorSession()
  {
    terminate(process, false);
    wait(process);
    delete process;
  }

  virtual Future<Option<string>> authenticate()
  {
    return dispatch(
        process, &KerberosAuthenticatorSessionProcess::authenticate);
  }

private:
  KerberosAuthenticatorSessionProcess* process;
};

class KerberosAuthenticatorProcess :
  public Process<KerberosAuthenticatorProcess>
{
public:
  KerberosAuthenticatorProcess() :
    ProcessBase(ID::generate("kerberos_authenticator")) {}

  virtual ~KerberosAuthenticatorProcess() {}

  Future<Option<string>> authenticate(const UPID& pid)
  {
    VLOG(1) << "Starting authentication session for " << pid;

    if (sessions.contains(pid)) {
      return Failure("authentication session already active");
    }

    Owned<KerberosAuthenticatorSession> session(
      new KerberosAuthenticatorSession(pid));

    sessions.put(pid, session);

    return session->authenticate()
      .onAny(defer(self(), &Self::_authenticate, pid));
  }

  virtual void _authenticate(const UPID& pid)
  {
    if (sessions.contains(pid)) {
      VLOG(1) << "Authentication sessions cleanup for " << pid;
      sessions.erase(pid);
    }
  }

private:
  hashmap <UPID, Owned<KerberosAuthenticatorSession>> sessions;
};

Try<Authenticator*> KerberosAuthenticator::create()
{
  return new KerberosAuthenticator();
}

KerberosAuthenticator::KerberosAuthenticator() : process(NULL) {}

KerberosAuthenticator::~KerberosAuthenticator()
{
  if (process != NULL) {
    terminate(process);
    wait(process);
    delete process;
  }
}


Try<Nothing> KerberosAuthenticator::initialize(
  const Option<Credentials>& credentials)
{
  static Once* initialize = new Once();

  // The 'error' is set at most once per os process.
  // To allow subsequent calls to return the possibly set Error
  // object, we make this a static pointer.
  static Option<Error>* error = new Option<Error>();

  if (process != NULL) {
    return Error("Authenticator intiialzed already");
  }

  // Initialize SASL and add the auxiliary memory plugin.  We must
  // not do this more than once per os-process.
  if (!initialize->once()) {
    LOG(INFO) << "Initializing server SASL";

    int result = sasl_server_init(NULL, "mesos");

    if (result != SASL_OK) {
      *error = Error(
          string("Failed to initialize SASL: ") +
          sasl_errstring(result, NULL, NULL));
    }

    initialize->done();
  }

  if (error->isSome()) {
    return error->get();
  }

  process = new KerberosAuthenticatorProcess();
  spawn(process);

  return Nothing();
}


Future<Option<string>> KerberosAuthenticator::authenticate(
    const UPID& pid)
{
  if (process == NULL) {
    return Failure("authenticator not initialized");
  }
  return dispatch(
    process, &KerberosAuthenticatorProcess::authenticate, pid);
}

} // namespace kerberos {
} // namespace internal {
} // namespace mesos {

#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif
