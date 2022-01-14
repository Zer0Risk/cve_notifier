#!/usr/local/bin/python3
import traceback,time,configparser,smtplib,re,os,requests,json,datetime,urllib3,logging

os.chdir(os.path.dirname(__file__))
logging.basicConfig(filename="cve_notifier.log", encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s ', datefmt='%d.%m.%Y %H:%M:%S')
config = configparser.ConfigParser()
acknowledged_cves_file = "acknowledged_cves.txt"
keywords_file = "keywords.txt"
program_start = datetime.datetime.today()
logging.info("cve_notifier started")


def get_keywords():
    keywords = []
    try:
        ### START Remove duplicate Spaces START ###
        with open(keywords_file, "r") as file:
            file_content = file.read()
        file_content = re.sub(" {2,100}", " ", file_content)
        with open(keywords_file, "w") as file:
            file.write(file_content)
        ### END Remove duplicate Spaces END ###

        with open(keywords_file, "r") as file:
            for lines in file.readlines():
                keyword_array = []
                seperators = ["_", "-", "."]
                if(lines.startswith("#")):
                    continue
                for x in range(lines.count(" ") + 1):
                    keyword_array.append(lines.split(" ")[x].capitalize())
                if(" " in lines):
                    for seperator in seperators:
                        keywords.append(f"{seperator}".join(keyword_array).lower().strip())
                        keywords.append(f"{seperator}".join(keyword_array).upper().strip())
                        keywords.append(f"{seperator}".join(keyword_array).strip())

                keywords.append(lines.strip())
                keywords.append(lines.lower().strip())
                keywords.append(lines.capitalize().strip())
                keywords.append(lines.upper().strip())
            logging.debug(f"get_keywords() returns following keywords: {keywords}")
            return keywords

    except FileNotFoundError as not_found:
        with open(keywords_file, "w+") as file:
            file.write("")

    except Exception:
        logging.error(f"get_keywords() Exception occurred: {traceback.format_exc()}")
        traceback.print_exc()



def acknowledge_cve(cve_id):
    if(not os.path.exists(acknowledged_cves_file)):
        with open(acknowledged_cves_file, "w+") as file:
            file.write("")

    with open(acknowledged_cves_file, "a+") as file:
        logging.info(f"Acknowledging following CVE: {cve_id}")
        file.write(cve_id+";")



def is_acknowledged_cve(cve_id):
    if (not os.path.exists(acknowledged_cves_file)):
        with open(acknowledged_cves_file, "w+") as file:
            file.write("")

    with open(acknowledged_cves_file, "r") as file:
        acknowledged_cves = file.read()

    for cve in acknowledged_cves.split(";"):
        if cve_id in cve:
            logging.info(f"{cve_id} is acknowledged")
            return True
    logging.info(f"{cve_id} is not acknowledged")
    return False



def get_cvss_rated_cves():
    cves = []
    severity = ["HIGH", "CRITICAL"]
    while(True):
        try:
            for x in severity:
                for cve_json in requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=250&cvssV3Severity={x}").json()["result"]["CVE_Items"]:
                    for keyword in get_keywords():
                        if keyword in str(cve_json) and \
                        datetime.datetime.strptime(cve_json["publishedDate"].split("T")[0], "%Y-%m-%d") > program_start:
                            logging.debug(f'get_cvss_rated_cves() Found following CVE {cve_json["cve"]["CVE_data_meta"]["ID"]}')
                            cve_json["keyword"] = keyword
                            cves.append(cve_json)
                            break
            logging.debug(f"get_cvss_rated_cves() returns")
            return cves

        except json.decoder.JSONDecodeError:  # if api is unavailable (HTTP Return Code 503)
            logging.warning(f"get_cvss_rated_cves() error occurred: {traceback.format_exc()}")
            time.sleep(5 * 60)
            continue

        except urllib3.exceptions.NewConnectionError:
            logging.warning(f"get_cvss_rated_cves() error occurred: {traceback.format_exc()}")
            time.sleep(5 * 60)
            continue

        except Exception:
            logging.error(f"get_cvss_rated_cves() error occurred: {traceback.print_exc()}")
            traceback.print_exc()
            time.sleep(5)



def send_message(messenger, cve_json, custom_message = None):

    if(custom_message == None):
        cve_published_date = cve_json["publishedDate"]
        cve_id = cve_json["cve"]["CVE_data_meta"]["ID"]
        cve_attack_vector = cve_json["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
        cve_attack_complexity = cve_json["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]
        cve_user_interaction = cve_json["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]
        cve_description = cve_json["cve"]["description"]["description_data"][0]["value"]
        cve_severity = cve_json["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        cve_keyword = cve_json["keyword"]
        logging.info(f"send_message() sending {cve_id} via {messenger}")


        message = f"""New Vulnerability found.
ID: {cve_id}
Published: {cve_published_date}
Matched Keyword: {cve_keyword}
Severity: {cve_severity}
Attack Vector: {cve_attack_vector}
Attack Complexity: {cve_attack_complexity}
User Interaction: {cve_user_interaction}
Details: https://nvd.nist.gov/vuln/detail/{cve_id}
Description: {cve_description} 
"""
    else:
        logging.info(f"send_message() sending custom message via {messenger}")
        message=custom_message

    config.read("config.ini")
    if(messenger=="telegram"):
        try:
            chat_id=config[messenger]["chat_id"]
            bot_token=config[messenger]["bot_token"]
            data = {"chat_id": chat_id, "text": message}
            res = requests.post(f"https://api.telegram.org/bot{bot_token}/sendMessage", json=data)
            if(res.status_code==200):
                return 0
            else:
                raise Exception(f"Telegram API Request failed, because \'{ res.json()['description'] }\'")
        except Exception:
            print(f"Error occurred in {messenger} send message function: " + traceback.format_exc() + f"\nCheck {messenger} Config Values in config.ini")
            logging.error(f"send_message() sending via {messenger} failed: {traceback.format_exc()}")
            return 1


    if(messenger=="email"):
        try:
            smtp_server =  config[messenger]["smtp_server"]
            smtp_port = config[messenger]["smtp_port"]
            sender = config[messenger]["sender"]
            receiver = config[messenger]["receiver"]
            message = f"""From: <{sender}>
To: <{receiver}>
Subject: New CVE found!
""" + message

            with smtplib.SMTP(str(smtp_server), int(smtp_port)) as server:
                if(config[messenger]["anonymous_login"] == 'False'):
                    username = config[messenger]["username"]
                    password = config[messenger]["password"]
                    server.login(username, password)
                    server.sendmail(sender, receiver, message.encode('ascii', 'replace'))
                    return 0
        except Exception:
            print(f"Error occurred in {messenger} send message function: " + traceback.format_exc() + f"\nCheck {messenger} Config Values in config.ini")
            logging.error(f"send_message() sending via {messenger} failed: {traceback.format_exc()}")
            return 1


    if(messenger=="mattermost"):
        try:
            json = {"text": message}
            res=requests.post(config[messenger]["webhook_url"], json=json)
            if(res.status_code == 200):
                return 0
            else:
                return 1

        except Exception:
            print(f"Error occurred in {messenger} send message function: " + traceback.format_exc() + f"\nCheck {messenger} Config Values in config.ini")
            logging.error(f"send_message() sending via {messenger} failed: {traceback.format_exc()}")
            return 1



def main():
    try:
        logging.info("main loop started")
        while(True):
            config.read("config.ini")
            for cve in get_cvss_rated_cves():
                for sending_method in config["method"].keys():
                    if( not is_acknowledged_cve(cve["cve"]["CVE_data_meta"]["ID"]+str(sending_method)) ):
                        if( send_message(sending_method, cve) != 1 ):
                            acknowledge_cve(cve["cve"]["CVE_data_meta"]["ID"]+str(sending_method))
            time.sleep(60 * 5)
    except Exception:
        print("Error occurred in main: " + traceback.format_exc())
        logging.error(f"main() Error occurred: {traceback.format_exc()}")

    finally:
        for sending_method in config["method"].keys():
            send_message(sending_method, "", "The cve notifier Process stopped, if this is not intended, review the logs")
        logging.debug(f"cve_notifier stopped")



if  __name__  == '__main__':
    main()
