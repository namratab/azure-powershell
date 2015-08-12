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

using System;
using Microsoft.Azure.Commands.Resources.Models.ActiveDirectory;
using Microsoft.Azure.Management.Authorization.Models;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Azure.Common.Authentication.Models;

namespace Microsoft.Azure.Commands.Resources.Models.Authorization
{
    internal static class AuthorizationClientExtensions
    {
        public const string CustomRole = "CustomRole";

        public static PSRoleDefinition ToPSRoleDefinition(this RoleDefinition role)
        {
            PSRoleDefinition roleDefinition = null;

            if (role != null)
            {
                roleDefinition = new PSRoleDefinition
                {
                    Name = role.Properties.RoleName,
                    Actions = new List<string>(role.Properties.Permissions.SelectMany(r => r.Actions)),
                    NotActions = new List<string>(role.Properties.Permissions.SelectMany(r => r.NotActions)),
                    Id = role.Id,
                    AssignableScopes = role.Properties.AssignableScopes.ToList(),
                    Description = role.Properties.Description,
                    IsCustom = role.Properties.Type == CustomRole ? true : false
                };
            }

            return roleDefinition;
        }

        public static PSRoleAssignment ToPSRoleAssignment(this RoleAssignment role, AuthorizationClient policyClient, ActiveDirectoryClient activeDirectoryClient)
        {
            PSRoleDefinition roleDefinition = policyClient.GetRoleDefinition(role.Properties.RoleDefinitionId);
            PSADObject adObject = activeDirectoryClient.GetADObject(new ADObjectFilterOptions { Id = role.Properties.PrincipalId.ToString() }) ?? new PSADObject() { Id = role.Properties.PrincipalId };

            if (adObject is PSADUser)
            {
                return new PSUserRoleAssignment()
                {
                    RoleAssignmentId = role.Id,
                    DisplayName = adObject.DisplayName,
                    Actions = roleDefinition.Actions,
                    NotActions = roleDefinition.NotActions,
                    RoleDefinitionName = roleDefinition.Name,
                    Scope = role.Properties.Scope,
                    UserPrincipalName = ((PSADUser)adObject).UserPrincipalName,
                    Mail = ((PSADUser)adObject).Mail,
                    ObjectId = adObject.Id
                };
            }
            else if (adObject is PSADGroup)
            {
                return new PSGroupRoleAssignment()
                {
                    RoleAssignmentId = role.Id,
                    DisplayName = adObject.DisplayName,
                    Actions = roleDefinition.Actions,
                    NotActions = roleDefinition.NotActions,
                    RoleDefinitionName = roleDefinition.Name,
                    Scope = role.Properties.Scope,
                    Mail = ((PSADGroup)adObject).Mail,
                    ObjectId = adObject.Id
                };
            }
            else if (adObject is PSADServicePrincipal)
            {
                return new PSServiceRoleAssignment()
                {
                    RoleAssignmentId = role.Id,
                    DisplayName = adObject.DisplayName,
                    Actions = roleDefinition.Actions,
                    NotActions = roleDefinition.NotActions,
                    RoleDefinitionName = roleDefinition.Name,
                    Scope = role.Properties.Scope,
                    ServicePrincipalName = ((PSADServicePrincipal)adObject).ServicePrincipalName,
                    ObjectId = adObject.Id
                };
            }
            else
            {
                return new PSRoleAssignment()
                {
                    RoleAssignmentId = role.Id,
                    DisplayName = adObject.DisplayName,
                    Actions = roleDefinition.Actions,
                    NotActions = roleDefinition.NotActions,
                    RoleDefinitionName = roleDefinition.Name,
                    Scope = role.Properties.Scope,
                    ObjectId = adObject.Id
                };
            }
        }

        public static PSAccessAssignment ToPsAccessAssignment(this PSRoleAssignment psRoleAssignment, AuthorizationClient policyClient, ActiveDirectoryClient activeDirectoryClient, string currentSubscriptionName)
        {
            PSRoleDefinition roleDefinition = policyClient.GetRoleRoleDefinition(psRoleAssignment.RoleDefinitionName);
            PSADObject subject =
                activeDirectoryClient.GetADObject(new ADObjectFilterOptions {Id = psRoleAssignment.ObjectId.ToString()}) ??
                new PSADObject() {Id = psRoleAssignment.ObjectId};

            ScopeDetails scopeDetails = GetScopeDetails(psRoleAssignment.Scope, currentSubscriptionName);
            PSAccessAssignment psAccessAssignment = new PSAccessAssignment()
            {
                RoleDefinitionId = roleDefinition == null ? null : roleDefinition.Id,
                RoleDefinitionName = psRoleAssignment.RoleDefinitionName,
                Scope = psRoleAssignment.Scope,
                ScopeType = scopeDetails.ScopeType,
                ScopeName = scopeDetails.ScopeName,
                SubjectId = subject.Id.ToString()
            };

            if (subject is PSADUser)
            {
                psAccessAssignment.SubjectName = ((PSADUser) subject).UserPrincipalName;
                psAccessAssignment.SubjectType = "User";
            }
            else if (subject is PSADGroup)
            {
                psAccessAssignment.SubjectName = ((PSADGroup)subject).Mail;
                psAccessAssignment.SubjectType = "Group";
            }
            else if (subject is PSADServicePrincipal)
            {
                psAccessAssignment.SubjectName = ((PSADServicePrincipal)subject).ServicePrincipalName;
                psAccessAssignment.SubjectType = "Service Principal";
            }
            else
            {
                psAccessAssignment.SubjectName = subject.DisplayName;
                psAccessAssignment.SubjectType = null;
            }

            return psAccessAssignment;
        }

        public static PSAccessAssignment ToPsAccessAssignment(this ClassicAdministrator classicAdministrator, ActiveDirectoryClient activeDirectoryClient, string currentSubscriptionName, string currentSubscriptionId)
        {
            return new PSAccessAssignment()
            {
                RoleDefinitionId = null,
                RoleDefinitionName = classicAdministrator.Properties.Role,
                Scope = "/subscriptions/" + currentSubscriptionId,
                ScopeType = "Subscription",
                ScopeName = currentSubscriptionName,
                SubjectId = null,
                SubjectName = classicAdministrator.Properties.EmailAddress,
                SubjectType = "User"
            };
        }

        private static ScopeDetails GetScopeDetails(string scope, string currentSubscriptionName)
        {
            string[] scopeParts = scope.Split(new[] {'/'}, StringSplitOptions.RemoveEmptyEntries);
            string scopeLowerCase = scope.ToLower();
            string scopeName = scopeParts[scopeParts.Length - 1];

            ScopeDetails scopeDetails = new ScopeDetails();

            if (scopeLowerCase.Contains("subscriptions") && scopeParts.Length <= 2)
            {
                scopeDetails.ScopeName = currentSubscriptionName;
                scopeDetails.ScopeType = "Subscription";
            }
            else if (scopeLowerCase.Contains("resourcegroups") && scopeParts.Length <= 4)
            {
                scopeDetails.ScopeName = scopeName;
                scopeDetails.ScopeType = "Resource group";
            }
            else if (scopeLowerCase.Contains("providers") && scopeParts.Length > 5)
            {
                scopeDetails.ScopeName = scopeName;
                scopeDetails.ScopeType = "Resource";
            }

            return scopeDetails;
        }

        private class ScopeDetails
        {
            public string ScopeName { get; set; }

            public string ScopeType { get; set; }
        }
    }
}
