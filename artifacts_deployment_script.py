from logging import info as _info, error as _error
from threading import Thread as _Thread
from urllib3 import disable_warnings as _disable_warnings
from urllib3.exceptions import InsecureRequestWarning as _InsecureRequestWarning
from multiprocessing import cpu_count as _cpu_count
from base64 import b64encode as _b64encode
from requests import post as _post
from xml.etree import cElementTree as ET
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import sys

_disable_warnings(_InsecureRequestWarning)
WAIT_TIME = 5
MAX_RUN_COUNT = _cpu_count()
responseResult = []


class _SoapConsumeUpload:
    def __init__(self, targetURL, targetUserName, targetPassword, reportLocalPath):
        self.targetWsdlURL = targetURL + "/analytics-ws/saw.dll?SoapImpl="
        self.targetUserName = targetUserName
        self.targetPassword = targetPassword
        self.header = {"Content-Type": "text/xml;charset=UTF-8"}
        self.reportLocalPath = reportLocalPath

    def _callPostMethod(self, body, soup_service, timeout=60, verify=False, **kargs):
        _message = kargs.get('message')
        _url = kargs.get('url', self.targetWsdlURL)
        _header = kargs.get('header', self.header)
        response = _post(_url+soup_service, data=body, headers=_header, verify=verify,
                         timeout=timeout)
        print('{_message} : {status}'.format(_message=_message, status=response.status_code))
        return response


    def get_session_token(self):
        body = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
            xmlns:v6="urn://oracle.bi.webservices/v6">
            <soapenv:Header/>
            <soapenv:Body>
            <v6:logon>
            <v6:name>{user}</v6:name>
            <v6:password>{passs}</v6:password>
            </v6:logon>
            </soapenv:Body>
            </soapenv:Envelope>'''.format(user=self.targetUserName, passs=self.targetPassword)

        token = self._callPostMethod(body, soup_service="nQSessionService", message='Genrating Session Token')
        token = ET.fromstring(str(token.content.decode("utf-8")))[0][0][0].text
        return token

    def create_folder_structure(self, path, session_id):
        body = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
        xmlns:v6="urn://oracle.bi.webservices/v6">
                        <soapenv:Header/>
                        <soapenv:Body>
                        <v6:createFolder>
                        <v6:path>/shared{path}</v6:path>
                        <v6:createIfNotExists>true</v6:createIfNotExists>
                        <v6:createIntermediateDirs>true</v6:createIntermediateDirs>
                        <v6:sessionID>{sessionid}</v6:sessionID>
                        </v6:createFolder>
                        </soapenv:Body>
                        </soapenv:Envelope>'''.format(path=path, sessionid=session_id)
        cfs = self._callPostMethod(body, soup_service="webCatalogService",
                                      message='Create Folder Structure if not Exist')
        content = str(cfs.content.decode("utf-8"))


    def uploadObject(self, path, session_id):
        print('Upload object processs started for {path}'.format(path=path))
        responseMessage = '_error : File failed to uploaded : ' + path
        artifact_indv_sec_data = {
            "name": "#name#",
            "contains_error": "#contains_error#",
            "payload": "#payload#"
        }
        try:
            fileName, fileExtension, fileExtension2 = path.split('/')[-1].split('.')
            fileLocation = '{path}/{fileName}.{fileExtension}.{fileExtension2}'.format(path=self.reportLocalPath, fileName=fileName,
                                                                      fileExtension=fileExtension, fileExtension2=fileExtension2)
            objectZippedData = _b64encode(open(fileLocation, 'rb').read()).decode('utf-8')
            body = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
            xmlns:v6="urn://oracle.bi.webservices/v6">
                        <soapenv:Header/>
                        <soapenv:Body>
                            <v6:pasteItem2>
                            <v6:archive>{objectZippedData}</v6:archive>
                            <v6:replacePath>/shared{path}</v6:replacePath>
                            <v6:flagACL>1</v6:flagACL>
                            <v6:flagOverwrite>1</v6:flagOverwrite>
                            <v6:sessionID>{sessionid}</v6:sessionID>
                        </v6:pasteItem2>
                        </soapenv:Body>
            </soapenv:Envelope>'''.format(path="/".join(path.split("/")[:-1]), fileExtension=fileExtension, objectZippedData=objectZippedData, sessionid=session_id)
            response = self._callPostMethod(body, message='Upload Function Called', soup_service="webCatalogService")
            content = str(response.content.decode("utf-8"))
            response = ET.fromstring(content)
            artifact_indv_sec_data["name"] = artifact_indv_sec_data["name"].replace("#name#", path.split('/')[-1])
            if "faultstring" not in content:
                responseMessage = 'Success : File uploaded successfully : ' + path
                print("File uploaded successfully")
                artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].replace(
                    "#contains_error#", "no")
            else:
                faultString = response[0][0][1].text
                responseMessage = '_error : %s : %s' % (faultString.__str__().replace(':', ''), path)
                artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].replace(
                    "#contains_error#", "yes")

        except Exception as e:
            _error(str(e))
            responseMessage = '_error : %s : %s' % (e.__str__().replace(':', ''), path)
            artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].replace(
                "#contains_error#", "yes")

            print('Upload processs completed for {path} -- {responseMessage}'.format(path=path,
                                                                                     responseMessage=responseMessage))
        finally:
            if 'REPORT' not in artifact_indv_sec["section"]:
                artifact_indv_sec["section"].append("REPORT")
                artifact_indv_sec["section_data"]["REPORT"] = []
            artifact_indv_sec_data["payload"] = artifact_indv_sec_data["payload"].replace("#payload#", responseMessage)
            artifact_indv_sec["section_data"]["REPORT"].append(artifact_indv_sec_data)
            return responseMessage


def multiThreadingUploadBI(SoapObj, reportRelativePath, session_id):
    print('uploadBI processs started for {reportRelativePath}'.
          format(reportRelativePath=reportRelativePath))
    responseString = SoapObj.uploadObject(reportRelativePath.strip(), session_id=session_id)
    responseResult.append(responseString)
    print('uploadBI processs completed for {reportRelativePath}'.format(reportRelativePath=reportRelativePath))


def uploadBI(url, user_name, password, reportRelativePath, reportLocalPath):
    session_id = ''
    print('uploadBI processs started')
    print('MAX_RUN_COUNT: {MAX_RUN_COUNT}'.format(MAX_RUN_COUNT=MAX_RUN_COUNT))
    print('WAIT_TIME: {WAIT_TIME}'.format(WAIT_TIME=WAIT_TIME))
    artifact_indv_sec["deployment_info"]["report_env"] = artifact_indv_sec["deployment_info"]["report_env"].replace(
        "##report_env##", url)
    soapConsumeObject = _SoapConsumeUpload(targetURL=url, targetUserName=user_name, targetPassword=password,
                                           reportLocalPath=reportLocalPath)
    if session_id == '':
        session_id = soapConsumeObject.get_session_token()

        for item in reportRelativePath.split(","):
            soapConsumeObject.create_folder_structure("/".join(item.split("/")[:-1]), session_id)
            threadList = [_Thread(target=multiThreadingUploadBI, args=(soapConsumeObject, path, session_id), name=path)
                          for path in
                          reportRelativePath.split(',')]

            for i in range(0, len(threadList), MAX_RUN_COUNT):
                runThreadList = threadList[i:i + MAX_RUN_COUNT]
                _info(runThreadList)
                [i.start() for i in runThreadList]
                [i.join() for i in runThreadList]
            print('uploadBI processs finsished')
            print("UploadBI process finished", responseResult)
            return ';'.join(responseResult)


#####################################################Integrations Deployments#############################
def act_deactivate_iar(id, status):  # Activate and deactivate the integrations using this method
    iar_deac_act_url = '/ic/api/integration/v1/integrations/'
    headers = {'X-HTTP-Method-Override': 'PATCH', 'Accept': 'application/json'}
    if status == "ACTIVATED":
        payload = {'status': 'ACTIVATED'}
        iar_act = requests.post(url+iar_deac_act_url+str(id), headers=headers,
                                auth=HTTPBasicAuth(user, passs), json=payload)
    else:
        payload = {'status': 'CONFIGURED'}
        iar_act = requests.post(url + iar_deac_act_url+id, headers=headers,
                                auth=HTTPBasicAuth(user, passs), json=payload)
    iar_act = json.loads(iar_act.content)
    if iar_act["status"] != status:
        print("{id} : {title}".format(id=id, title=iar_act["title"]))
        return "Error"
    else:
        print("{id}: {status}!".format(id=id, status=status))
        return "Success"


def deploy_filepath(method, filepath, file_source_location):
        iar_import_url = '/ic/api/integration/v1/integrations/archive'
        print("{method}ting the integrations for: {filepath}".format(filepath=filepath, method=method))
        files = {
            'file': open(file_source_location+filepath, 'rb'),
            'type': (None, 'application/octet-stream'),
        }
        o_iar_deploy = requests.request(method, url + iar_import_url, headers=headers,
                                        auth=HTTPBasicAuth(user, passs),
                                        files=files)
        if str(o_iar_deploy.status_code).startswith("20"):
            print("{filepath}: DEPLOYED".format(filepath=filepath))
            print("Activating Integration....")
            act_result = act_deactivate_iar(os.path.splitext(filepath)[0], "ACTIVATED")
            if act_result == "Success":
                print("{file_name}: ACTIVATED".format(file_name=filepath))
                raise Exception("SUCCESS: {file_name} ACTIVATED and DEPLOYED".format(file_name=filepath))
            elif act_result == "Error":
                print("{file_name}: got error while ACTIVATING".format(file_name=filepath))
                raise Exception("ERROR: {file_name} got error while ACTIVATING".format(file_name=filepath))
        else:
            o_iar_deploy = json.loads(o_iar_deploy.content)
            if o_iar_deploy["status"] == "HTTP 500 Internal Server Error":
                raise Exception("ERROR: "+o_iar_deploy["status"] + o_iar_deploy["title"])


def deploy_par(method, filepath, file_source_location):
    par_import_url = '/ic/api/integration/v1/packages/archive'
    files = {
        'file': open(file_source_location+filepath, 'rb'),
        'type': (None, 'application/octet-stream'),
    }
    pkg_import = requests.request(method, url + par_import_url, headers=headers, auth=HTTPBasicAuth(user, passs),
                               files=files)
    if str(pkg_import.status_code).startswith("20"):
        print("{filepath}: DEPLOYED".format(filepath=filepath))
        raise Exception("SUCCESS: {filepath}: DEPLOYED".format(filepath=filepath))
    else:
        o_par_deploy = json.loads(pkg_import.content)
        print("{filepath}: NOT DEPLOYED ".format(filepath=filepath))
        print("Error: {error}".format(error=o_par_deploy["detail"]))
        raise Exception("ERROR: {error}".format(error=o_par_deploy["detail"]))


def upload_integrations(url, user, passs, V_FILEPATHS, file_source_location):
    #Intialize variable values
    print("Recieved Filepath: {V_FILEPATHS}".format(V_FILEPATHS=V_FILEPATHS))
    print("Iterating over filepaths and processing for deployment......")
    import_put_post = 'put'
    iar_check_url = '/ic/api/integration/v1/integrations/'
    par_check_url = '/ic/api/integration/v1/packages/'
    artifact_type = "OIC"
    if 'OIC' not in artifact_indv_sec["section"]:
        artifact_indv_sec["section"].append(artifact_type)
        artifact_indv_sec["section_data"][artifact_type] = []
    artifact_indv_sec["deployment_info"]["oic_env"] = artifact_indv_sec["deployment_info"]["oic_env"].replace(
        "##oic_env##", url)

    for filepath in V_FILEPATHS:
        print("###################################{filepath}###############################".format(filepath=filepath))
        artifact_indv_sec_data={
            "name": "#name#",
            "contains_error": "#contains_error#",
            "payload": "#payload#"
        }
        if filepath.lower().endswith(".par"):
            try:
                filetype = "PAR"
                print("FileType: PACKAGE ARCHIVE")
                print("{filepath}: Deployment has been started".format(filepath=filepath))
                #Checking the status of the package
                #checking the staus of the package
                o_par_statu = requests.get(url+par_check_url+os.path.splitext(filepath)[0], headers=headers,
                                           auth=HTTPBasicAuth(user, passs))
                o_par_status = json.loads(o_par_statu.content)
                if o_par_statu.status_code != 200:
                    print("Package Not Found. Deploying.......")
                    import_put_post = "post"
                elif str(o_par_statu.status_code).startswith("20"):
                    print("{filepath}: package found".format(filepath=filepath))
                    iar_list = o_par_status["integrations"]
                    print("Integrations list", iar_list)
                    for iar in iar_list:
                        iar_status = iar["status"]
                        print("Deactivate the integration if activated")
                        if iar_status == "ACTIVATED":
                            act_result = act_deactivate_iar(iar["id"], "CONFIGURED")
                            if act_result == "Success":
                                print("{file_name}: DE_ACTIVATED".format(file_name=iar["name"]))
                            elif act_result == "Error":
                                print("{file_name}: Got error while DE_ACTIVATING".format(file_name=iar["name"]))
                                raise Exception("ERROR: {file_name} got error while DE_ACTIVATING".
                                                format(file_name=iar["name"]))
                print("Deploying Package")
                deploy_par(import_put_post, filepath, file_source_location)
            except Exception as e:
                print("{e}".format(e=e))
                artifact_indv_sec_data['name'] = artifact_indv_sec_data['name'].replace("#name#", filepath)
                artifact_indv_sec_data["payload"] = artifact_indv_sec_data["payload"].replace("#payload#", str(e))

                if str(e).split(":")[0] == "ERROR":
                    artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].\
                        replace("#contains_error#", "yes")

                elif str(e).split(":")[0] == "SUCCESS":
                    artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].replace(
                    "#contains_error#", "no")
                artifact_indv_sec["section_data"][artifact_type].append(artifact_indv_sec_data)

        elif filepath.lower().endswith(".iar"):
            try:
                fileName, fileExtension = filepath.split('-')[0].strip(), filepath.split('-')[1].strip().split(".")[-1]
                version = ".".join(filepath.split("-")[1].strip().split(".")[:-1])
                filetype = "IAR"
                print("Checking the status of the {filepath} integration".format(filepath=filepath))
                o_iar_status = requests.get(url+iar_check_url+fileName+"|"+version, headers=headers,
                                            auth=HTTPBasicAuth(user, passs))
                # If the status is ACTIVATED
                o_iar_status = json.loads(o_iar_status.content)
                if o_iar_status["status"] == "ACTIVATED":
                    print("Integrations Status: ACTIVATED")
                    print("Deactivating the integrations..")
                    #Deactivating the IAR Integration
                    act_result = act_deactivate_iar(os.path.splitext(filepath)[0], "CONFIGURED")
                    if act_result == "Success":
                        print("SUCCESS: {file_name} DE_ACTIVATED".format(file_name=filepath))
                    elif act_result == "Error":
                        print("{file_name}: got error while DE_ACTIVATING".format(file_name=filepath))
                        raise Exception("ERROR: {file_name} got error while DE_ACTIVATING".format(file_name=filepath))

                elif o_iar_status["status"] == "HTTP 404 Not Found":
                    print("Integration not found")
                    import_put_post = 'post'

                else:
                    print("Integration Status: CONFIGURED")
                #Deploying Integration
                print("Deploying Integration....")
                deploy_filepath(import_put_post, filepath, file_source_location)

            except Exception as e:
                print("{e}".format(filepath=filepath, e=e))
                print(artifact_indv_sec_data)
                artifact_indv_sec_data['name'] = artifact_indv_sec_data['name'].replace("#name#", filepath)
                artifact_indv_sec_data["payload"] = artifact_indv_sec_data["payload"].replace("#payload#", str(e))

                if str(e).split(":")[0] == "ERROR":
                    artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].\
                        replace("#contains_error#", "yes")
                elif str(e).split(":")[0] == "SUCCESS":
                    artifact_indv_sec_data["contains_error"] = artifact_indv_sec_data["contains_error"].replace(
                        "#contains_error#", "no")
                print(artifact_indv_sec_data)
                artifact_indv_sec["section_data"][artifact_type].append(artifact_indv_sec_data)


def create_json(json_file):
    obj_count = 0
    artifact_status = []
    for item in json_file["section"]:
        obj_count += len(json_file["section_data"][item])
        for value in json_file["section_data"][item]:
            if value["contains_error"] == "yes":
                artifact_status.append(1)
            elif value["contains_error"] == "no":
                artifact_status.append(0)

    json_file["deployment_info"]["status"] = json_file["deployment_info"]["status"].\
        replace("##status##", 'Contains Error' if any(artifact_status) == True else 'Deployment Successfully Done')
    json_file["deployment_info"]["obj_count"] = json_file["deployment_info"]["obj_count"].replace("##obj_count##",
                                                                                                  str(obj_count))

    json_obj = json.dumps(json_file, indent=4)
    with open("json.json", "w") as file:
        file.write(json_obj)


def read_json(json_file):
    f = open(json_file, "r")
    return json.loads(f.read())


if __name__ == "__main__":
    json_file_path = sys.argv[1]
    artifact_indv_sec = read_json(json_file_path + "artifact_indv.json")
    artifact_indv_sec_data = read_json(json_file_path + "artifact_indv_sec_data.json")
    input_file = json.loads(sys.argv[2])
    conn_details = json.loads(sys.argv[3])

    if "REPORTS" in input_file.keys():
        print("Reports Migrations Started")
        url = conn_details["URL"][input_file["REPORTS"]["target_instance"]]
        password = conn_details["PASSWORD"][input_file["REPORTS"]["target_instance"]]
        username = conn_details["USERNAME"][input_file["REPORTS"]["target_instance"]]
        report_list = input_file["REPORTS"]["report_list"]
        source_repo = input_file["REPORTS"]["source_repo"]
        print(url, username, password, report_list, source_repo)
        a = uploadBI(url, username, password, report_list, source_repo)
        print("Reports Migrations has been completed")
    if "OIC" in input_file.keys():
        print("OIC Migrations started!!!!")
        user = conn_details["USERNAME"][input_file["OIC"]["target_instance"]]
        passs = conn_details["PASSWORD"][input_file["OIC"]["target_instance"]]
        url = conn_details["URL"][input_file["OIC"]["target_instance"]]
        file_source_location = input_file["OIC"]["source_repo"]
        oic_filepath = input_file["OIC"]["OIC_list"].split(",")
        headers = {'X-HTTP-Method-Override': 'PATCH', 'Accept': 'application/json'}
        print(url, user, passs, oic_filepath)
        upload_integrations(url, user, passs, oic_filepath, file_source_location)

    create_json(artifact_indv_sec)

