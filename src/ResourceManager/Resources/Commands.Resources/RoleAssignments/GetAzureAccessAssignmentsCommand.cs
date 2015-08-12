// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.Azure.Commands.Resources.Models;
using Microsoft.Azure.Commands.Resources.Models.ActiveDirectory;
using Microsoft.Azure.Commands.Resources.Models.Authorization;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace Microsoft.Azure.Commands.Resources
{
    /// <summary>
    /// Filters role assignments
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureAccessAssignments"), OutputType(typeof(List<PSAccessAssignment>))]
    public class GetAzureAccessAssignmentsCommand : ResourcesBaseCmdlet
    {
        [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true, HelpMessage = "The principal UPN or Display Name or Email.")]
        [ValidateNotNullOrEmpty]
        public string PrincipalDisplayNameOrUpnOrEmail { get; set; }

        public override void ExecuteCmdlet()
        {
            WriteObject(PoliciesClient.GetAccessAssignments(PrincipalDisplayNameOrUpnOrEmail, Profile.Context.Subscription.Name), true);
        }
    }
}