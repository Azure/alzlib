package alzlib

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// PolicyAssignmentsParameterValues represents a data structure for replacing policy parameters.
// The first map key is the assignment name, the second is the parameter name, and the value is
// the parameter values value (an ARM SDK type).
type PolicyAssignmentsParameterValues map[string]map[string]*armpolicy.ParameterValuesValue

// Merge merges the other PolicyAssignmentsParameterValues into this one.
func (papv PolicyAssignmentsParameterValues) Merge(other PolicyAssignmentsParameterValues) PolicyAssignmentsParameterValues {
	if other == nil {
		return papv
	}
	for assignment, parametermap := range other {
		// If assignment doesn't exist in original, create it.
		if _, ok := papv[assignment]; !ok {
			papv[assignment] = make(map[string]*armpolicy.ParameterValuesValue)
		}
		// Merge the parameter values.
		for parameter, value := range parametermap {
			papv[assignment][parameter] = value
		}
	}
	return papv
}

// getWellKnownPolicyAssignmentParameterValues is used by the *Archetype.WithWellKnownPolicyValues() method to
// set the values for well-known policy assignment parameters.
// It takes the well known values, e.g. for LA workspace and location, and merges them with the policy assignments
// known to the ALZ library.
func getWellKnownPolicyAssignmentParameterValues(wkpv *WellKnownPolicyValues) PolicyAssignmentsParameterValues {
	const (
		privateDnsZoneProviderPath = "/providers/Microsoft.Network/privateDnsZones"
	)
	res := make(PolicyAssignmentsParameterValues)
	if wkpv == nil {
		return res
	}
	if wkpv.DefaultLocation != nil {
		res.upsertParameterValue("Deploy-Log-Analytics", "automationRegion", *wkpv.DefaultLocation)
		res.upsertParameterValue("Deploy-Log-Analytics", "workspaceRegion", *wkpv.DefaultLocation)
		res.upsertParameterValue("Deploy-MDFC-Config", "ascExportResourceGroupLocation", *wkpv.DefaultLocation)
	}
	if wkpv.DefaultLogAnalyticsWorkspaceId != nil {
		res.upsertParameterValue("Deploy-AzActivity-Log", "logAnalytics", *wkpv.DefaultLogAnalyticsWorkspaceId)
		res.upsertParameterValue("Deploy-AzSqlDb-Auditing", "logAnalyticsWorkspaceId", *wkpv.DefaultLogAnalyticsWorkspaceId)
		res.upsertParameterValue("Deploy-MDFC-Config", "logAnalytics", *wkpv.DefaultLogAnalyticsWorkspaceId)
		res.upsertParameterValue("Deploy-Resource-Diag", "logAnalytics", *wkpv.DefaultLogAnalyticsWorkspaceId)
		res.upsertParameterValue("Deploy-VM-Monitoring", "logAnalytics_1", *wkpv.DefaultLogAnalyticsWorkspaceId)
		res.upsertParameterValue("Deploy-VMSS-Monitoring", "logAnalytics_1", *wkpv.DefaultLogAnalyticsWorkspaceId)
	}
	if wkpv.PrivateDnsZoneResourceGroupId != nil {
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureAcrPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azurecr.io", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureAppPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azconfig.io", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureAppServicesPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azurewebsites.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureAsrPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.siterecovery.windowsazure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureAutomationDSCHybridPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-automation.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureAutomationWebhookPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-automation.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureBatchPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.batch.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCognitiveSearchPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.search.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCognitiveServicesPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.cognitiveservices.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCosmosCassandraPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.cassandra.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCosmosGremlinPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.gremlin.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCosmosMongoPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.mongo.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCosmosSQLPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.documents.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureCosmosTablePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.table.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureDataFactoryPortalPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.adf.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureDataFactoryPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.datafactory.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureDiskAccessPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureEventGridDomainsPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.eventgrid.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureEventGridTopicsPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.eventgrid.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureEventHubNamespacePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.servicebus.windows.ne", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureFilePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.afs.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureHDInsightPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azurehdinsight.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureIotHubsPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-devices.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureIotPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-devices-provisioning.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureKeyVaultPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.vaultcore.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMachineLearningWorkspacePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.api.azureml.ms", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMediaServicesKeyPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.media.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMediaServicesLivePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.media.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMediaServicesStreamPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.media.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMigratePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.prod.migration.windowsazure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMonitorPrivateDnsZoneId1", fmt.Sprintf("%s%s/privatelink.monitor.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMonitorPrivateDnsZoneId2", fmt.Sprintf("%s%s/privatelink.oms.opinsights.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMonitorPrivateDnsZoneId3", fmt.Sprintf("%s%s/privatelink.ods.opinsights.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMonitorPrivateDnsZoneId4", fmt.Sprintf("%s%s/privatelink.agentsvc.azure-automation.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureMonitorPrivateDnsZoneId5", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureRedisCachePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.redis.cache.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureServiceBusNamespacePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.servicebus.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureSignalRPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.service.signalr.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageBlobPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageBlobSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageDFSPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.dfs.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageDFSSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.dfs.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageFilePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.file.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageQueuePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.queue.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageQueueSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.queue.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageStaticWebPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.web.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureStorageStaticWebSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.web.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureSynapseDevPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.dev.azuresynapse.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureSynapseSQLODPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.sql.azuresynapse.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureSynapseSQLPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.sql.azuresynapse.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-Dns-Zones", "azureWebPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.webpubsub.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
	}
	return res
}

func (papv PolicyAssignmentsParameterValues) upsertParameterValue(assignment, parameter string, value any) {
	if _, ok := papv[assignment]; !ok {
		papv[assignment] = make(map[string]*armpolicy.ParameterValuesValue)
	}
	papv[assignment][parameter] = &armpolicy.ParameterValuesValue{
		Value: value,
	}
}
