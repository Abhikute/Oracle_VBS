import json
import sys
import io

html_files_path = sys.argv[1]
data = json.loads(sys.argv[2])

# json_file_path = "json.json"

# with open(json_file_path, 'r') as j:
#      contents = json.loads(j.read())
# data = contents

# artifact_summary_file = html_files_path+"artifact_summary.html"
# artifact_title = html_files_path+"artifact_title.html"
# artifact_deployment_info = html_files_path+"deployment_info.html"
# artifact_row_details = html_files_path+"row_details.html"

artifact_summary_file = html_files_path+"artifact_summary.html"
artifact_section_details = html_files_path+"section_details.html"
artifact_deployment_info = html_files_path+"deployment_info.html"
artifact_row_details = html_files_path+"row_details.html"


def read_html_file(html_file_path):
    with open("{file_path}".format(file_path=html_file_path), "r") as artifact_summary:
        file = [line.strip() for line in artifact_summary.readlines()]
        file = "".join(file)
        artifact_summary.close()
    return file

def get_deployment_summ_details(artifact_deployment_info):
    deployment_info = data["deployment_info"]
    artifact_deployment_info = artifact_deployment_info.format(status=deployment_info['status'], obj_count=deployment_info['obj_count'],
                                    report_env=deployment_info['report_env'], oic_env=deployment_info['oic_env'],
                                    db_env=deployment_info['db_env'])
    return artifact_deployment_info


def create_row_details(json_data, artifact_row_details_info, artifacts_section_details):
    result = []
    for section in json_data["section"]:
        section_det = []
        for item in json_data["section_data"][str(section)]:
            if item["contains_error"] == "yes":

                section_det.append(artifact_row_details_info.format(name=item["name"], contains_error=item["contains_error"],
                                                               payload=item["payload"], row_color="danger"))
            else:
                section_det.append(artifact_row_details_info.format(name=item["name"], contains_error=item["contains_error"],
                                                               payload=item["payload"], row_color="success"))

        result.append(artifacts_section_details.format(section=section.title(), row_details="".join(section_det)))

    return result

def create_html_file(html_file, artifact_deployment_info, artifact_row_details_info, artifacts_section_details):
    deployment_info_file = get_deployment_summ_details(artifact_deployment_info).encode('utf-8').strip()
    artifacts_details = u''.join(create_row_details(data, artifact_row_details_info, artifacts_section_details)).encode('utf-8').strip()
    html_file = html_file.format(deployment_information=deployment_info_file, section_details=artifacts_details)
    with io.open("artifact_summary.html", "w", encoding='utf8') as html:
        html.write(html_file.decode('utf-8'))
        html.close()
    return "File has been created!!"


final_html = read_html_file(artifact_summary_file)
artifact_deployment_info = read_html_file(artifact_deployment_info)
artifact_row_details_info = read_html_file(artifact_row_details)
artifacts_section_details = read_html_file(artifact_section_details)

print(create_html_file(final_html, artifact_deployment_info, artifact_row_details_info, artifacts_section_details))
