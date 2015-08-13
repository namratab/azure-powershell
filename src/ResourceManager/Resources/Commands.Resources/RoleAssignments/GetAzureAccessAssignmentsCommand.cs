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
using System.Collections.Generic;
using System.Management.Automation;

namespace Microsoft.Azure.Commands.Resources
{
    /// <summary>
    /// Gets all principals having access to the subscription
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureAccessAssignments", DefaultParameterSetName = ParameterSet.Empty), OutputType(typeof(List<PSAccessAssignment>))]
    public class GetAzureAccessAssignmentsCommand : ResourcesBaseCmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ParameterSet.UPN, HelpMessage = "The user UPN or email.")]
        [ValidateNotNullOrEmpty]
        public string UserUpnOrEmail { get; set; }

        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ParameterSet.Mail, HelpMessage = "The group display name.")]
        [ValidateNotNullOrEmpty]
        public string GroupDisplayName { get; set; }

        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ParameterSet.SPN, HelpMessage = "The service principal display name.")]
        [ValidateNotNullOrEmpty]
        public string ServicePrincipalDisplayName { get; set; }

        public override void ExecuteCmdlet()
        {
            PrincipalType principalType = PrincipalType.None;
            ADObjectFilterOptions options = new ADObjectFilterOptions();

            if (!string.IsNullOrWhiteSpace(UserUpnOrEmail))
            {
                options.UPN = UserUpnOrEmail;
                options.Mail = UserUpnOrEmail;
                principalType = PrincipalType.User;
            }
            else if (!string.IsNullOrWhiteSpace(GroupDisplayName))
            {
                options.SearchString = GroupDisplayName;
                principalType = PrincipalType.Group;
            }
            if (!string.IsNullOrWhiteSpace(ServicePrincipalDisplayName))
            {
                options.SearchString = ServicePrincipalDisplayName;
                principalType = PrincipalType.ServicePrincipal;
            }

            WriteObject(PoliciesClient.GetAccessAssignments(options, principalType, Profile.Context.Subscription.Name), true);
        }
    }
}