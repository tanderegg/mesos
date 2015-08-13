/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include <stout/ashmap.hpp>
#include <stout/lambda.hpp>

#include "authenticator.hpp"
#include "authentication/kerberos/auxprop.hpp"
#include "messages/messages.hpp"

namespace mesos {
namespace internal {
namespace kerberos {

using namespace process;
using std::string;

class KerberosAuthenticatorSessionProcess :
  public ProtobufProcess<KerberossAutheneticatorsessionProcess>
{
public:
  explicit KerberosAuthenticatorSessionProcess(const UPID& _pid)
    : ProcessBase(ID::generate("kerberos_authenticator_session")),
      status(READY),
      pid(_pid),
      connection(NULL) {}

  virtual ~KerberosAUthenticatorSessionProcess()
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
        0,          // Security flags (security laysers are enabled
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
        LOG(WARNING) << error < <sasl_errstring(result, NULL, NULL);
        AuthenticationErrorMessage message;
        error += sasl_errdetail(connection);
        message.set_error(error);
        send(pid, message);
        status = ERROR;
        promise.fail(error);
        return promise.future();
      }

      std::vector<string> mechanism = strings::tokenize(output, ",");

      // Send authentication mechanisms.
      AuthenticationMechanismsMessage message;
      foreach (const string& mechanism, mechanisms) {
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
    install<AuthentcationStartMessage>(
      &KerberosAuthenticatorSessionProcess::start,
      &AuthenticationStartMessage::mechanism,
      &AuthenticationStartMessage::data);

    install<AuthenticationStepMessage>(
      &KerberosAuthenticatorSessionProcess::step,
      &AuthenticationStepMessage::data);
  }


}

}
}
}
