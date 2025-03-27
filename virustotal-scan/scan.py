# Project description
# Checks and scans a file or URL for potential malicious behavior using virustotal API


import vt
import re
import datetime
import hashlib
import argparse
import os
from dotenv import load_dotenv

# environment variable loader
load_dotenv()

API_KEY = os.getenv('API_KEY')

# converts epoch to datetime string
def epochToDate(date):
    return datetime.datetime.fromtimestamp(date).strftime('%Y-%m-%d %H:%M:%S')

# computes SHA-256 hash of file
def fileHash(filepath, algorithm='sha256'):
    hash_function = hashlib.new(algorithm)

    try:
        with open(filepath, 'rb') as file:
            while chunk := file.read(8192):
                hash_function.update(chunk)
        return hash_function.hexdigest()
    
    except FileNotFoundError:
        print("File could not be found")

    except ValueError:
        print("Hashing algorithm is not valid")


def checkFile(filepath):

    path_regex = r"([a-zA-Z]:)?([\\/][\w\s\.-]+)+\.[\w]+"

    if not re.search(path_regex, filepath):
        raise Exception("Not a valid file path")

    client = vt.client(API_KEY)

    try:
        # get file SHA-256 hash
        hash = fileHash(filepath)

        # look up file
        file = client.get_object(hash)

        # print out general information
        print("General Information:" + "\n" + "========================================")
        print("File size: " + file.get("size"))
        print("File type: " + file.get("type_tag"))
        print("File tags: " + file.get("tags"))
        print("File's VT community reputation: " + file.get("reputation"))
        print("First submission date to VirusTotal: " + epochToDate(file.get("first_submission_date")))
        print("Last submission date: " + file.get("last_submission_date"))
        print("Last modification date: " + file.get("last_modification_date"))
        print("\n")

        # print hash information
        print("Hash Information" + "\n" + "========================================")
        print("SHA-256 hash: " + file.get("sha256"))
        print("SHA-1 hash: " + file.get("sha1"))
        print("MD5 hash: " + file.get("md5"))
        print("\n")

        # print file names
        print("File's names" + "\n" + "========================================")
        print("All names:" + file.get("names"))
        print("Most interesting name: " + file.get("meaningful_name"))
        print("\n")

        # print last analysis results
        print("Last Analysis" + "\n" + "========================================")
        print("Last analysis date: " + epochToDate(file.get("last_analysis_date")) + "\n")
        print("Last analysis results: " + "\n")

        results = file.get("last_analysis_results")

        if results:
            for result_name, result_data in results.items():
                print("Engine Name: " + result_name)
                for attribute, value in result_data.items():
                    if value == None:
                        print(attribute + ": None")
                    else:
                        print(attribute + ": " + str(value))
                print("\n")
        else:
            print("No previous analysis results found")
        
        # print last scan results
        print("Last analysis summary: " + "\n")

        stats = file.get("last_analysis_stats")

        if stats:
            for attribute, value in stats.items():
                if value == None:
                    print(attribute + ": None")
                else:
                    print(attribute + ": " + str(value))
        else:
            print("No previous analysis stats found")

        # print sandbox verdicts
        print("Sandbox Verdicts" + "\n" + "========================================")

        sandbox = file.get("sandbox_verdicts")

        for sandbox_name, sandbox_data in sandbox.items():
            print("Sandbox name: " + sandbox_name)

            for attribute, value in sandbox_data.items():
                if value == None:
                    print(attribute + ": None")
                else:
                    print(attribute + ": " + str(value))

   
    except:
        raise Exception("Error")


def checkURL(url):

    url_regex = r"/^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$/"

    if not re.search(url_regex, url):
        raise Exception("Not a valid URL")
    
    client = vt.client(API_KEY)

    

    return

if __name__ == "__main__":

    # define parser
    parser = argparse.ArgumentParser(
        description="Malware scanner that accepts file paths or URLs as arguments"
    )

    parser.add_argument(
        "-f", "--file_path", metavar="file_path", required=False, help="The relative path of the file to be analyzed"
    )

    """parser.add_argument(
        "-d", "--detail", metavar="detail", required=False, help="The level of detail desired"
    )"""

    parser.add_argument(
        "-u", "--url", metavar="url", required=False, help="The URL to be analyzed"
    )

    args = parser.parse_args()

    if "url" in args and "file_path" in args:
        checkFile(args.file_path)
        checkURL(args.url)
    elif "url" in args and not "file_path" in args:
        checkURL(args.url)
    elif "file_path" in args:
        checkFile(args.file_path)
    else:
        print("No arguments provided")