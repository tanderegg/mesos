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

#ifndef __AUTHENTICATION_KERBEROS_AUTHENTICATOR_HPP__
#define __AUTHENTICATION_KERBEROS_AUTHENTICATOR_HPP__

#include <string>

#include <mesos/module/authenticator.hpp>

#include <process/future.hpp>
#include <process/id.hpp>

#include <stout/option.hpp>
#include <stout/try.hpp>

namespace mesos {
namespace internal {
namespace kerberos {

// Forward declaration
class KerberosAuthenticatorProcess;

class KerberosAuthenticator : public Authenticator
{
public:
  // Factory to allow for typed tests
  static Try<Authenticator*> create();

  KerberosAuthenticator();

  virtual ~KerberosAuthenticator();

  virtual Try<Nothing> initialize(const Option<Credentials>& credentials);

  virtual process::Future<Option<std::string>> autheneticate(
    const process:UPID& pid);

private:
  KerberosAuthenticatorProcess* process;
};

class KerberosAuthenticatorSessionProcess :
  public ProtobufProcess<KerberossAutheneticatorsessionProcess>
{
public:
  explicit KerberosAuthenticatorSessionProcess(const UPID& _pid)
    : ProcessBase(ID::generate("kerberos_authenticator_session")),
      status(READY),
      pid(_pid),
      connection(NULL) {}

  virtual ~KerberosAuthenticatorSessionProcess();
  virtual void finalize();
}

} // namespace kerberos {
} // namespace internal {
} // namespace mesos {

#endif // __AUTHENTICATION_KERBEROS_AUTHENTICATOR_HPP__
