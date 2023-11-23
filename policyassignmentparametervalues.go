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
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureAcrPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azurecr.io", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureAppPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azconfig.io", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureAppServicesPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azurewebsites.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureAsrPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.siterecovery.windowsazure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureAutomationDSCHybridPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-automation.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureAutomationWebhookPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-automation.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureBatchPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.batch.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCognitiveSearchPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.search.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCognitiveServicesPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.cognitiveservices.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCosmosCassandraPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.cassandra.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCosmosGremlinPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.gremlin.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCosmosMongoPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.mongo.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCosmosSQLPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.documents.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureCosmosTablePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.table.cosmos.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureDataFactoryPortalPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.adf.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureDataFactoryPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.datafactory.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureDiskAccessPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureEventGridDomainsPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.eventgrid.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureEventGridTopicsPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.eventgrid.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureEventHubNamespacePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.servicebus.windows.ne", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureFilePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.afs.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureHDInsightPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azurehdinsight.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureIotHubsPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-devices.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureIotPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.azure-devices-provisioning.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureKeyVaultPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.vaultcore.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMachineLearningWorkspacePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.api.azureml.ms", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMediaServicesKeyPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.media.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMediaServicesLivePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.media.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMediaServicesStreamPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.media.azure.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMigratePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.prod.migration.windowsazure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMonitorPrivateDnsZoneId1", fmt.Sprintf("%s%s/privatelink.monitor.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMonitorPrivateDnsZoneId2", fmt.Sprintf("%s%s/privatelink.oms.opinsights.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMonitorPrivateDnsZoneId3", fmt.Sprintf("%s%s/privatelink.ods.opinsights.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMonitorPrivateDnsZoneId4", fmt.Sprintf("%s%s/privatelink.agentsvc.azure-automation.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureMonitorPrivateDnsZoneId5", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureRedisCachePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.redis.cache.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureServiceBusNamespacePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.servicebus.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureSignalRPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.service.signalr.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageBlobPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageBlobSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.blob.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageDFSPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.dfs.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageDFSSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.dfs.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageFilePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.file.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageQueuePrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.queue.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageQueueSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.queue.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageStaticWebPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.web.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureStorageStaticWebSecPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.web.core.windows.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureSynapseDevPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.dev.azuresynapse.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureSynapseSQLODPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.sql.azuresynapse.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureSynapseSQLPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.sql.azuresynapse.net", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
		res.upsertParameterValue("Deploy-Private-DNS-Zones", "azureWebPrivateDnsZoneId", fmt.Sprintf("%s%s/privatelink.webpubsub.azure.com", *wkpv.PrivateDnsZoneResourceGroupId, privateDnsZoneProviderPath))
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
