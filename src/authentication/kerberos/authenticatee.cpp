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

#include "authentication/kerberos/authenticatee.hpp"

#include <stddef.h>   // For size_t needed by sasl.h.

#include <sasl/sasl.h>

#include <string>

#include <process/defer.hpp>
#include <process/dispatch.hpp>
#include <process/once.hpp>
#include <process/process.hpp>
#include <process/protobuf.hpp>

#include <stout/strings.hpp>

#include "logging/logging.hpp"

#include "messages/messages.hpp"

namespace mesos {
namespace internal {
namespace kerberos {

using namespace process;
using std::string;

class KerberosAuthenticateeProcess
  : public ProtobufProcess<KerberosAuthenticateeProcess>
{
public:
  KerberosAuthenticateeProcess(
      const Credential& _credential,
      const UPID& _client)
    : ProcessBase(ID::generate("kerberos_authenticatee")),
      credential(_credential),
      client(_client),
      status(READY),
      connection(NULL)
    {
      const char* data = credential.secret().data();
      size_t length = credential.secret().length();

      secret = (sasl_secret_t*) malloc(sizeof(sasl_secret_t) + length);

      CHECK(secret != NULL) << "Failed to allocate memory for secret";

      memcpy(secret->data, data, length);
      secret->len = length;
    }

    virtual ~KerberosAuthenticateeProcess()
    {
      if (connection != NULL) {
        sasl_dispose(&connection);
      }
      free(secret);
    }

    virtual void finalize()
    {
      discarded(); // Fail the promise
    }

    Future<bool> authenticate(const UPID& pid)
    {
        static Once* initialize = new Once();
        static bool initialized = false;

        if (!initalize->once()) {
          LOG(INFO) << "Initializing client SASL";
          int result = sasl_client_init(NULL);
          if (result != SASL_OK) {
            status = ERROR;
            string error(sasl_errstring(result, NULL, NULL));
            promise.fail("Failed to initialize SASL: " + error);
            initialize->done();
            return promise.future();
          }

          initialized = true;

          initialize->done();
        }

        if (!initialized) {
          promise.faile("Failed to initialize SASL");
          return promise.future();
        }

        if (status != READY) {
          return promise.future();
        }

        LOG(INFO) << "Creating new client SASL connection";

        callbacks[0].id = SASL_CB_GETREALM;
        callbacks[0].proc = NULL;
        callbacks[0].context = NULL;

        callbacks[1].id = SASL_CB_USER;
        callbacks[1].proc = (int(*)()) &user;
        callbacks[1].context = (void*) credential.principal().c_str()

        callbacks[2].id = SASL_CB_AUTHNAME;
        callbacks[2].proc = (int(*)()) &user;
        callbacks[2].context = (void*) secret;

        callbacks[3].id = SASL_CB_PASS;
        callbacks[3].proc = (int(*)()) &pass;
        callbacks[3].context = (void*) secret;

        callbacks[4].id = SASL_CB_LIST_END;
        callbacks[4].proc = NULL;
        callbacks[4].context = NULL;

        int result = sasl_client_new(
            "mesos",    // Registered name of service.
            NULL,       // Server's FQDN.
            NULL, NULL, // IP address information strigns.
            callbacks,  // Callbacks supported only for this connection
            0,          // Security flags (security layers are enabled
                        // using security properties, separately).
            &connection);

        if (result != SASL_OK) {
          status = ERROR;
          string error(sasl_errstring(result, NULL, NULL));
          promise.fail("Failed to create client SASL connection: " + error);
          return promise.future();
        }

        AuthenticateMessage message;
        message.set_pid(client);
        send(pid, message);

        status = STARTING;

        // Stop authenticating if nobody cares.
        promise.future().onDiscard(defer(self(), &Self::discarded));

        return promise.future();
    }
}

Future<bool> KerberosAuthenticatee::authenticate(
    const UPID& pid,
    const UPID& client,
    const mesos::Credential& credential)
{
  if (!credential.has_secret()) {
    LOG(WARNING) << "Authentication failed; secret needed by Kerberos "
                 << "authenticatee";

    return false;
  }

  CHECK(process == NULL);
  process = new KerberosAuthenticateeProcess(credential, client);
  spawn(process);

  return dispatch(
      process, &KerberosAuthenticateeProcess::authenticate, pid);
}

} // namespace cram_md5 {
} // namespace internal {
} // namespace mesos {
