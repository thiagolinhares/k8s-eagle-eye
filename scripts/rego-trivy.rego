# METADATA
# title: trivy-operator-custom-defectdojo
# scope: package
package postee.trivyoperator.custom.defectdojo  

title:="-" #not used with webhook

get_month_from_date(timestamp) = month {
    ts := timestamp
    t := time.parse_rfc3339_ns(ts)
    month := time.date(t)[1]
}

get_month_name_from_date(timestamp) = month_name {
    dict := {
        1: "January",
        2: "February",
        3: "March",
        4: "April",
        5: "May",
        6: "June",
        7: "July",
        8: "August",
        9: "September",
        10: "October",
        11: "November",
        12: "December"
    }
    month_name := dict[get_month_from_date(timestamp)]
}

format_to_dd_date(timeStamp) = dd_date {
    ts := timeStamp
    t := time.parse_rfc3339_ns(ts)
    dd_date := sprintf("%04d-%02d-%02d", [time.date(t)[0], time.date(t)[1], time.date(t)[2]])
}

image_name := sprintf("%s/%s", [input.operatorObject.report.registry.server, input.operatorObject.report.artifact.repository])
image_version := input.operatorObject.report.artifact.tag
image_full_name := sprintf("%s:%s", [image_name, image_version])

# this following JSON structure's format is dictated by how the
# underlying CURL command is expecting the incoming JSON payload
# to look like.
dd_data:= {
  "defectdojo": {
    "verb": input.verb,
    "scan": input.operatorObject,
    "metadata": {
      "active": true,
      "verified": false,
      "engagement_name": sprintf("FedRamp Audit - %s", [get_month_name_from_date(input.operatorObject.metadata.creationTimestamp)]),
      "environment": "Lab",
      "minimum_severity": "Low",
      "product_name": "k8s-poc",
      "product_type_name": "kubernetes_cluster",
      "auto_create_context": true,
      "scan_date": format_to_dd_date(input.operatorObject.metadata.creationTimestamp),
      "scan_type": "Trivy Operator Scan",
      "test_title": input.operatorObject.metadata.name,
      "service": image_name,
      "version": image_version,
      "group_by": "component_name",
      "close_old_findings": false,
      "clode_old_findings_product_scope": false,
      "deduplication_on_engagement": true,
      "do_not_reactivate": false,
      "tags": [sprintf("image=%s", [image_full_name]), sprintf("namespace=%s", [input.operatorObject.metadata.labels["trivy-operator.resource.namespace"]]), sprintf("name=%s", [input.operatorObject.metadata.labels["trivy-operator.resource.name"]]), sprintf("container=%s", [input.operatorObject.metadata.labels["trivy-operator.container.name"]]), sprintf("kind=%s", [input.operatorObject.metadata.labels["trivy-operator.resource.kind"]])]
    }
  }
}

result:= dd_data