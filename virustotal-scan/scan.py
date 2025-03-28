# Project description
# Checks and scans a file or URL for potential malicious behavior using virustotal API


import vt
import re
import datetime
import hashlib
import argparse
import sys
import os
from dotenv import load_dotenv

# environment variable loader
load_dotenv()

API_KEY = os.getenv('API_KEY')

# converts epoch to datetime string
def epochToDate(date):
    if not date:
        return "None"
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

    #if not re.search(path_regex, filepath):
        #raise Exception("Not a valid file path")

    with vt.Client(API_KEY) as client:
        try:
            # get file SHA-256 hash
            hash = fileHash(filepath)

            print("hash: " + hash)

            # look up file
            file = client.get_object(f"/files/{hash}")

            # print out general information
            print("General Information:" + "\n" + "========================================")
            print("File size: " + str(file.get("size")))
            print("File type: " + str(file.get("type_tag")))
            print("File tags: " + ', '.join(file.get("tags")))
            print("Is downloadable: " + str(file.get("downloadable")))
            print("# of times submitted: " + str(file.get("times_submitted")))
            print("First submission date to VirusTotal: " + epochToDate(file.get("first_submission_date")))
            print("Last submission date: " + epochToDate(file.get("last_submission_date")))
            print("Last modification date: " + epochToDate(file.get("last_modification_date")))
            print("\n")

            # print hash information
            print("Hash Information" + "\n" + "========================================")
            print("SHA-256 hash: " + str(file.get("sha256")))
            print("SHA-1 hash: " + str(file.get("sha1")))
            print("MD5 hash: " + str(file.get("md5")))
            print("\n")

            # print file names
            print("File's names" + "\n" + "========================================")
            print("All names:" + ', '.join( file.get("names")))
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

            print("\n")

            # print sandbox verdicts
            print("Sandbox Verdicts" + "\n" + "========================================")

            sandbox = file.get("sandbox_verdicts")

            if sandbox:

                for sandbox_name, sandbox_data in sandbox.items():
                    print("Sandbox name: " + sandbox_name)

                    for attribute, value in sandbox_data.items():
                        if value == None:
                            print(attribute + ": None")
                        else:
                            print(attribute + ": " + str(value))

            else:
                print("No sandbox results")

            print("\n")

            # reputation and verdict
            reputation = file.get("reputation")
            votes = file.get("total_votes")

            print("Reputation and votes" + "\n" + "========================================")

            if votes:
                print("Total # of harmless and malicious votes:")
                for attribute, value in votes.items():
                    if value:
                        print(attribute + ": " + str(value))
                    else:
                        print(attribute + ": None")
            else:
                print("No votes")

            print("\n")

            print("Reputation score = crowdsourced metric that reflects how users and security engines rate a file/URL" + "\n")
            print("Positive score = Likely trusted")
            print("Negative score = Likely malicious")
            print("Zero score: file has not been voted on by the community")
            print("\n")
            print("scanned file's reputation score: " + str(reputation))
            print("\n")

            verdict = ""

            if reputation > 0:
                verdict = "Likely safe"
            if reputation == 0:
                verdict = "Not enough information, proceed with caution"
            if reputation < 0:
                verdict = "Detecting multiple community members that flagged this file as malicious, are you certain whatever you're doing is worth it?"

            print("Final Verdict: " + verdict)
    
        except Exception as e:
            print(e)


def checkURL(url):

    url_regex = r"/^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$/"

    #if not re.search(url_regex, url):
        #raise Exception("Not a valid URL")
    
    client = vt.Client(API_KEY)

    try:

        url_id = vt.url_id(url)

        url_object = client.get_object("/urls/{}", url_id)

        # print out general information
        print("General Information:" + "\n" + "========================================")
        print("URL title: " + str(url_object.get("title")))
        print("URL tags: " + ', '.join(url_object.get("tags")))
        print("Has content: " + str(url_object.get("has_content")))

        meta = url_object.get("html_meta")

        for meta_key, meta_data in meta.items():
            print("Meta Tag Name: " + meta_key)
            if meta_data == None:
                print("Meta Tag Values: None")
            else:
                print("Meta Tag Values: " + ', '.join(meta_data))

        print("# of times submitted: " + str(url_object.get("times_submitted")))
        print("First submission date to VirusTotal: " + epochToDate(url_object.get("first_submission_date")))
        print("Last submission date: " + epochToDate(url_object.get("last_submission_date")))
        print("Last modification date: " + epochToDate(url_object.get("last_modification_date")))
        print("\n")

        # print last analysis results
        print("Last Analysis" + "\n" + "========================================")
        print("Last analysis date: " + epochToDate(url_object.get("last_analysis_date")) + "\n")
        print("Last analysis results: " + "\n")

        results = url_object.get("last_analysis_results")

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

        stats = url_object.get("last_analysis_stats")

        if stats:
            for attribute, value in stats.items():
                if value == None:
                    print(attribute + ": None")
                else:
                    print(attribute + ": " + str(value))
        else:
            print("No previous analysis stats found")
        
        print("\n")

        
        # tracker information
        print("Tracker information" + "\n" + "========================================")

        trackers = url_object.get("trackers")

        if trackers:
            for tracker_name, tracker_data in trackers.items():
                print("Tracker name: " + tracker_name)
                if tracker_data:
                    for attribute, value in tracker_data[0].items():
                        if not value:
                            print(attribute + ": None")
                        elif value and attribute == "timestamp":
                            print(attribute + ": " + epochToDate(value))
                        else:
                            print(attribute + ": " + value)
                else:
                    print("No tracker data found")

        print("\n")


        # Reputation and verdict
        reputation = url_object.get("reputation")
        votes = url_object.get("total_votes")

        print("Reputation and votes" + "\n" + "========================================")

        if votes:
            print("Total # of harmless and malicious votes:")
            for attribute, value in votes.items():
                if value:
                    print(attribute + ": " + str(value))
                else:
                    print(attribute + ": None")
        else:
            print("No votes")

        print("\n")

        print("Reputation score = crowdsourced metric that reflects how users and security engines rate a file/URL" + "\n")
        print("Positive score = Likely trusted")
        print("Negative score = Likely malicious")
        print("Zero score: URL has not been voted on by the community")
        print("\n")
        print("scanned URL's reputation score: " + str(reputation))
        print("\n")

        verdict = ""

        if reputation > 0:
            verdict = "Likely safe"
        if reputation == 0:
            verdict = "Not enough information, proceed with caution"
        if reputation < 0:
            verdict = "Detecting multiple community members that flagged this URL as malicious, are you certain whatever you're doing is worth it?"

        print("Final Verdict: " + verdict)


    
    except Exception as e:
        print(e)

    finally:
        client.close()

    

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

    if len(sys.argv) == 1:
        print("No arguments provided")
    else:
        args = parser.parse_args(sys.argv[1:])

        if args.url and args.file_path:
            print("File and URL provided, checking file and URL..." + "\n")
            checkFile(args.file_path)
            checkURL(args.url)
        elif args.url and not args.file_path:
            print("File not provided, checking URL..." + "\n")
            checkURL(args.url)
        elif args.file_path and not args.url:
            print("URL not provided, checking file..." + "\n")
            checkFile(args.file_path)