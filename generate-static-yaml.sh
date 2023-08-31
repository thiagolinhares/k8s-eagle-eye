#!/usr/bin/env bash


start () {
  # we need yq to mod few things
  if ! command -v yq &> /dev/null
  then
      echo "yq could not be found. Downloading executable..."
      wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O yq &> /dev/null
      chmod +x yq
      export YQ_BINARY=${PWD}/yq
  else
      export YQ_BINARY=$(which yq)
  fi

  if [[ ! -d rendered ]]; then
    mkdir rendered
  fi
}

render_trivy () {
  set -e

  version=$1
  output_dir=$(mktemp -p rendered -d)

  helm template trivy-operator \
    aqua/trivy-operator \
    --version ${version} \
    --namespace security-tools \
    --include-crds \
    --values helm-values/values-trivy-operator.yaml \
    --output-dir=${output_dir} 2>&1> /dev/null
  
  export helm_static=${output_dir}/trivy-operator
  
  # tweaks to the rendered manifests
  rm -rf ${helm_static}/templates/specs
  
  # change all ClusterRole to Role (namespace limited scope)
  sed -i 's/ClusterRole/Role/g' ${helm_static}/templates/rbac.yaml

  # hack persistent volumeclaimtemplate for trivy-server. 
  # PR to fix it accepted at: https://github.com/aquasecurity/trivy-operator/pull/1457
  $YQ_BINARY eval '(. | select(.kind == "StatefulSet") | del(.spec.volumeClaimTemplates)) // .' -i ${helm_static}/templates/trivy-server.yaml

  $YQ_BINARY eval '(. | select(.kind == "StatefulSet") | .spec.template.spec.volumes += [{"name": "data", "emptyDir": {} }]) // .' -i ${helm_static}/templates/trivy-server.yaml

  set +e
}

render_postee () {
  set -e
  
  version=$1
  output_dir=$(mktemp -p rendered -d)

  helm template postee \
    aqua/postee \
    --version ${version} \
    --namespace security-tools \
    --include-crds \
    --values helm-values/values-postee.yaml \
    --output-dir=${output_dir} 2>&1> /dev/null

  export postee_static=${output_dir}/postee

  # tweaks to the rendered manifests
  rm -rf ${postee_static}/templates/tests

  # we dont need UI at the moment
  rm -f ${postee_static}/templates/postee-ui*.yaml

  # remove volumeclaimtemplate postee.
  # PR to fix it: TO-DO
  $YQ_BINARY eval '(. | select(.kind == "StatefulSet") | del(.spec.volumeClaimTemplates)) // .' -i ${postee_static}/templates/postee.yaml

  # Create extra custom configmaps (not covered by Helm chart)
  kubectl -n security-tools create configmap postee-custom-templates --from-file=scripts/rego-trivy.rego --dry-run=client -oyaml > ${postee_static}/templates/configmap-postee-custom-templates.yaml
  kubectl -n security-tools create configmap postee-custom-scripts --from-file=scripts/dd-upload.sh --dry-run=client -oyaml > ${postee_static}/templates/configmap-postee-custom-scripts.yaml

  set +e
}

render_defectdojo () {
  set -e

  version=$1
  output_dir=$(mktemp -p rendered -d)

  helm template defectdojo \
    helm-charts/defectdojo \
    --version ${version} \
    --namespace security-tools \
    --include-crds \
    --values helm-values/values-defectdojo.yaml \
    --output-dir=${output_dir} 2>&1> /dev/null

  export defectdojo_static=${output_dir}/defectdojo

  # tweaks to the rendered manifests
  rm -rf ${defectdojo_static}/templates/tests

  set +e
}

# Call functions providing chart version

if [[ $1 == "trivy-operator" ]]; then
  start
  render_trivy 0.15.1
  echo -e "\nTrivy-Operator files: \t${helm_static}\n"

elif [[ $1 == "postee" ]]; then
  start
  render_postee 2.14.0
  echo -e "\nPostee files:         \t${postee_static}\n"

elif [[ $1 == "defectdojo" ]]; then
  start
  render_defectdojo 1.6.82
  echo -e "DefectDojo files:     \t${defectdojo_static}\n"

else
  echo -e "Usage: $0 <trivy-operator|postee|defectdojo>"
fi

echo -e "Please, check the rendered manifests and apply them to your cluster. \n"
