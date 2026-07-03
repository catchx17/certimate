package engine

import (
	"fmt"
	"log/slog"
	"maps"
	"strings"

	"github.com/certimate-go/certimate/internal/certmgmt"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/repository"
)

const (
	bizDeployStatusRunning   = "running"
	bizDeployStatusSucceeded = "succeeded"
	bizDeployStatusFailed    = "failed"
	bizDeployStatusSkipped   = "skipped"
)

/**
 * Inputs:
 *   - ref: "certificate": string
 *
 * Variables:
 *   - "node.skipped": boolean
 *   - "deployment.nodeId": string
 *   - "deployment.nodeName": string
 *   - "deployment.status": string
 *   - "deployment.skipped": boolean
 *   - "deployment.provider": string
 *   - "deployment.providerAccessId": string
 *   - "deployment.providerAccessName": string
 *   - "deployment.target": string
 *   - "deployment.targetType": string
 *   - "deployment.targetId": string
 *   - "deployment.targetHost": string
 *   - "deployment.targetDomains": string
 *   - "deployment.targetFiles": string
 *   - "deployment.targetNames": string
 *   - "deployment.targetPorts": string
 *   - "deployment.certificateId": string
 *   - "deployment.certificateCommonName": string
 *   - "deployment.certificateSubjectAltNames": string
 */
type bizDeployNodeExecutor struct {
	nodeExecutor

	accessRepo      accessRepository
	certificateRepo certificateRepository
	wfoutputRepo    workflowOutputRepository
}

func (ne *bizDeployNodeExecutor) Execute(execCtx *NodeExecutionContext) (*NodeExecutionResult, error) {
	execRes := newNodeExecutionResult(execCtx.Node)

	nodeCfg := execCtx.Node.Data.Config.AsBizDeploy()
	ne.logger.Info("ready to deploy certificate ...", slog.Any("config", nodeCfg))
	ne.setVariablesOfContext(execCtx, nodeCfg, nil, nil, bizDeployStatusRunning, false)

	// 查询上次执行结果
	lastOutput, err := ne.getLastOutputArtifacts(execCtx)
	if err != nil {
		ne.setVariablesOfContext(execCtx, nodeCfg, nil, nil, bizDeployStatusFailed, false)
		return execRes, err
	} else {
		if lastOutput != nil {
			ne.logger.Info(fmt.Sprintf("found last node output #%s record", lastOutput.RunId))
		}
	}

	// 获取前序节点输出证书
	var inputCertificate *domain.Certificate
	if inputState, ok := execCtx.inputs.Get(nodeCfg.CertificateOutputNodeId, "certificate"); ok {
		if inputStateValue, ok := inputState.Value.(string); ok {
			s := strings.Split(inputStateValue, "#")
			if len(s) == 2 {
				certificate, err := ne.certificateRepo.GetById(execCtx.Context(), s[1])
				if err != nil {
					ne.logger.Warn("could not get input certificate")
					ne.setVariablesOfContext(execCtx, nodeCfg, nil, nil, bizDeployStatusFailed, false)
					return execRes, err
				}

				inputCertificate = certificate
			}
		}
	}
	if inputCertificate == nil {
		ne.setVariablesOfContext(execCtx, nodeCfg, nil, nil, bizDeployStatusFailed, false)
		return execRes, fmt.Errorf("invalid input certificate")
	}
	ne.setVariablesOfContext(execCtx, nodeCfg, inputCertificate, nil, bizDeployStatusRunning, false)

	// 检测是否可以跳过本次执行
	if lastOutput != nil && inputCertificate.CreatedAt.Before(lastOutput.UpdatedAt) {
		if skippable, reason := ne.checkCanSkip(execCtx, lastOutput); skippable {
			ne.logger.Info(fmt.Sprintf("skip this deployment, because %s", reason))

			var providerAccess *domain.Access
			// 跳过时不因授权记录缺失改变原有执行结果。
			if access, err := ne.getProviderAccess(execCtx, nodeCfg.ProviderAccessId); err == nil {
				providerAccess = access
			}
			ne.setVariablesOfContext(execCtx, nodeCfg, inputCertificate, providerAccess, bizDeployStatusSkipped, true)
			execRes.AddVariableWithScope(execCtx.Node.Id, stateVarKeyNodeSkipped, true, stateValTypeBoolean)
			return execRes, nil
		} else if reason != "" {
			ne.logger.Info(fmt.Sprintf("re-deploy, because %s", reason))

			execRes.AddVariableWithScope(execCtx.Node.Id, stateVarKeyNodeSkipped, false, stateValTypeBoolean)
		}
	} else {
		execRes.AddVariableWithScope(execCtx.Node.Id, stateVarKeyNodeSkipped, false, stateValTypeBoolean)
	}

	// 读取部署提供商授权
	providerAccessConfig := make(map[string]any)
	providerAccess, err := ne.getProviderAccess(execCtx, nodeCfg.ProviderAccessId)
	if err != nil {
		ne.setVariablesOfContext(execCtx, nodeCfg, inputCertificate, nil, bizDeployStatusFailed, false)
		return nil, err
	}
	if providerAccess != nil {
		providerAccessConfig = providerAccess.Config
	}
	ne.setVariablesOfContext(execCtx, nodeCfg, inputCertificate, providerAccess, bizDeployStatusRunning, false)

	// 部署证书
	deployer := certmgmt.NewClient(certmgmt.WithLogger(ne.logger))
	deployReq := &certmgmt.DeployCertificateRequest{
		Provider:               domain.DeploymentProviderType(nodeCfg.Provider),
		ProviderAccessConfig:   providerAccessConfig,
		ProviderExtendedConfig: nodeCfg.ProviderConfig,
		CertificatePEM:         inputCertificate.Certificate,
		PrivateKeyPEM:          inputCertificate.PrivateKey,
	}
	if _, err := deployer.DeployCertificate(execCtx.Context(), deployReq); err != nil {
		ne.logger.Warn("could not deploy certificate")
		ne.setVariablesOfContext(execCtx, nodeCfg, inputCertificate, providerAccess, bizDeployStatusFailed, false)
		return execRes, err
	}
	ne.setVariablesOfContext(execCtx, nodeCfg, inputCertificate, providerAccess, bizDeployStatusSucceeded, false)

	// 节点输出
	execRes.outputForced = true

	ne.logger.Info("deployment completed")
	return execRes, nil
}

func (ne *bizDeployNodeExecutor) getLastOutputArtifacts(execCtx *NodeExecutionContext) (*domain.WorkflowOutput, error) {
	lastOutput, err := ne.wfoutputRepo.GetByWorkflowIdAndNodeId(execCtx.Context(), execCtx.WorkflowId, execCtx.Node.Id)
	if err != nil && !domain.IsRecordNotFoundError(err) {
		return nil, fmt.Errorf("failed to get last output record of node #%s: %w", execCtx.Node.Id, err)
	}

	return lastOutput, nil
}

func (ne *bizDeployNodeExecutor) checkCanSkip(execCtx *NodeExecutionContext, lastOutput *domain.WorkflowOutput) (_skip bool, _reason string) {
	thisNodeCfg := execCtx.Node.Data.Config.AsBizDeploy()

	if lastOutput != nil && lastOutput.Succeeded {
		// 比较和上次部署时的关键配置（即影响证书部署的）参数是否一致
		lastNodeCfg := lastOutput.NodeConfig.AsBizDeploy()

		if thisNodeCfg.ProviderAccessId != lastNodeCfg.ProviderAccessId {
			return false, "the configuration item 'ProviderAccessId' changed"
		}
		if !maps.Equal(thisNodeCfg.ProviderConfig, lastNodeCfg.ProviderConfig) {
			return false, "the configuration item 'ProviderConfig' changed"
		}

		if thisNodeCfg.SkipOnLastSucceeded {
			return true, "the last deployment already completed"
		}
	}

	return false, ""
}

func (ne *bizDeployNodeExecutor) getProviderAccess(execCtx *NodeExecutionContext, accessId string) (*domain.Access, error) {
	if accessId == "" {
		return nil, nil
	}

	access, err := ne.accessRepo.GetById(execCtx.Context(), accessId)
	if err != nil {
		return nil, fmt.Errorf("failed to get access #%s record: %w", accessId, err)
	}

	return access, nil
}

// 直接写入工作流上下文，确保部署失败后 Catch 分支中的通知节点也能读取。
func (ne *bizDeployNodeExecutor) setVariablesOfContext(execCtx *NodeExecutionContext, nodeCfg domain.WorkflowNodeConfigForBizDeploy, certificate *domain.Certificate, providerAccess *domain.Access, status string, skipped bool) {
	var certificateId string
	var certificateCommonName string
	var certificateSubjectAltNames string
	if certificate != nil {
		certificateId = certificate.Id
		certificateSubjectAltNames = certificate.SubjectAltNames
		certificateCommonName = strings.Split(certificate.SubjectAltNames, ";")[0]
	}

	var providerAccessName string
	if providerAccess != nil {
		providerAccessName = providerAccess.Name
	}

	deploymentTarget, deploymentTargetType, deploymentTargetId, deploymentTargetHost, deploymentTargetDomains, deploymentTargetFiles, deploymentTargetNames, deploymentTargetPorts := ne.getDeploymentTarget(nodeCfg)

	execCtx.variables.Set(stateVarKeyDeploymentNodeId, execCtx.Node.Id, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentNodeName, execCtx.Node.Data.Name, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentStatus, status, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentSkipped, skipped, stateValTypeBoolean)
	execCtx.variables.Set(stateVarKeyDeploymentProvider, nodeCfg.Provider, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentProviderAccessId, nodeCfg.ProviderAccessId, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentProviderAccessName, providerAccessName, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTarget, deploymentTarget, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetType, deploymentTargetType, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetId, deploymentTargetId, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetHost, deploymentTargetHost, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetDomains, deploymentTargetDomains, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetFiles, deploymentTargetFiles, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetNames, deploymentTargetNames, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentTargetPorts, deploymentTargetPorts, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentCertificateId, certificateId, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentCertificateCommonName, certificateCommonName, stateValTypeString)
	execCtx.variables.Set(stateVarKeyDeploymentCertificateSubjectAltNames, certificateSubjectAltNames, stateValTypeString)
}

func (ne *bizDeployNodeExecutor) getDeploymentTarget(nodeCfg domain.WorkflowNodeConfigForBizDeploy) (_target string, _targetType string, _targetId string, _targetHost string, _targetDomains string, _targetFiles string, _targetNames string, _targetPorts string) {
	providerConfig := nodeCfg.ProviderConfig
	if providerConfig == nil {
		return "", "", "", "", "", "", "", ""
	}

	targetType := ne.getDeploymentTargetType(providerConfig)
	targetId := getAllStringsFromProviderConfig(providerConfig,
		"loadbalancerId", "loadbalancerArn", "listenerId", "listenerArn", "instanceId", "instanceArn",
		"acceleratorId", "gatewayId", "proxyId", "vserverId", "hostId", "domainId",
		"distributionId", "distributionArn", "certificateId", "certificateArn", "certificateIdOrDesc",
		"resourceId", "resourceIds", "bucket", "pullZoneId", "poolId", "groupId", "siteId", "websiteId",
		"appId", "serviceId", "functionName", "namespace", "secretName", "webhookId", "zoneId", "spaceId")
	targetHost := getStringFromProviderConfig(providerConfig, "sshHost", "ftpHost", "host", "hostname", "server", "serverUrl", "webhookUrl")
	targetDomains := getStringsFromProviderConfig(providerConfig,
		"domains", "domain", "hosts", "domainName", "domainNames", "customDomain")
	targetFiles := getAllStringsFromProviderConfig(providerConfig,
		"filePathForCrt", "filePathForKey", "filePathForCrtOnlyServer", "filePathForCrtOnlyIntermedia",
		"objectKeyForCrt", "objectKeyForKey", "objectKeyForCrtOnlyServer", "objectKeyForCrtOnlyIntermedia",
		"certificatePath")
	targetNames := getAllStringsFromProviderConfig(providerConfig,
		"siteNames", "appName", "certificateName", "keyvaultName", "loadbalancerName", "nodeName",
		"serviceName", "spaceName", "workspace")
	targetPorts := getAllStringsFromProviderConfig(providerConfig, "listenerPort", "loadbalancerPort", "resourcePort", "sitePort", "ftpPort")

	parts := make([]string, 0)
	if targetType != "" {
		parts = append(parts, targetType)
	}
	if targetId != "" {
		parts = append(parts, targetId)
	}
	if targetHost != "" {
		parts = append(parts, targetHost)
	}
	if targetDomains != "" {
		parts = append(parts, targetDomains)
	}
	if targetFiles != "" {
		parts = append(parts, targetFiles)
	}
	if targetNames != "" {
		parts = append(parts, targetNames)
	}
	if targetPorts != "" {
		parts = append(parts, targetPorts)
	}

	return strings.Join(parts, ";"), targetType, targetId, targetHost, targetDomains, targetFiles, targetNames, targetPorts
}

func (ne *bizDeployNodeExecutor) getDeploymentTargetType(providerConfig map[string]any) string {
	if targetType := getStringsFromProviderConfig(providerConfig, "deployTarget", "targetType", "resourceType", "domainType", "hostType", "siteType", "serviceType", "secretType", "resourceProduct", "resourceProducts"); targetType != "" {
		return targetType
	}

	if value, ok := providerConfig["isDefault"].(bool); ok {
		if value {
			return "default"
		}

		return "sni"
	}

	return ""
}

func getStringFromProviderConfig(providerConfig map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := providerConfig[key]; ok {
			if s, ok := stringFromProviderConfigValue(value); ok {
				return s
			}
		}
	}

	return ""
}

func getStringsFromProviderConfig(providerConfig map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := providerConfig[key]; ok {
			switch v := value.(type) {
			case string:
				return v
			case []string:
				return strings.Join(v, ";")
			case []any:
				ss := make([]string, 0, len(v))
				for _, item := range v {
					if s, ok := stringFromProviderConfigValue(item); ok {
						ss = append(ss, s)
					}
				}
				return strings.Join(ss, ";")
			}
		}
	}

	return ""
}

func getAllStringsFromProviderConfig(providerConfig map[string]any, keys ...string) string {
	ss := make([]string, 0)
	for _, key := range keys {
		if value, ok := providerConfig[key]; ok {
			if s := strings.TrimSpace(strings.Trim(getStringsFromProviderConfig(map[string]any{key: value}, key), ";")); s != "" {
				ss = append(ss, s)
			}
		}
	}

	return strings.Join(ss, ";")
}

func stringFromProviderConfigValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case int:
		return fmt.Sprintf("%d", v), true
	case int32:
		return fmt.Sprintf("%d", v), true
	case int64:
		return fmt.Sprintf("%d", v), true
	case float64:
		return fmt.Sprintf("%.0f", v), true
	default:
		return "", false
	}
}

func newBizDeployNodeExecutor() NodeExecutor {
	return &bizDeployNodeExecutor{
		nodeExecutor:    nodeExecutor{logger: slog.Default()},
		accessRepo:      repository.NewAccessRepository(),
		certificateRepo: repository.NewCertificateRepository(),
		wfoutputRepo:    repository.NewWorkflowOutputRepository(),
	}
}
