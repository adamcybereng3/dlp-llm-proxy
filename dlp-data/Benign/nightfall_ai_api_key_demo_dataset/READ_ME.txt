# Sample Dataset for Testing API Key Detection

This sample dataset demonstrates Nightfall's advanced API key detection capabilities. The data has been fully de-identified and can be used to test PHI detection on any data loss prevention (DLP) platform.

## Background

This sample dataset demonstrates Nightfall's advanced API key detection capabilities. The data has been fully de-identified and can be used to test key detection on any data loss prevention platform.

API keys enable services to provide controlled programmatic access to APIs and identify authorized applications. However, a single exposed API key can compromise critical infrastructure and data.

Accurately detecting API keys in code is challenging. Traditional regex and heuristic-based solutions generate high false positive rates by flagging valid code as leaked secrets.

To address this issue, Nightfall AI uses advanced natural language processing (NLP) techniques to dramatically reduce false positives. Additionally, Nightfall identifies the status of detected keys to enable immediate remediation of active credentials.

## Positive Samples

In the positive test folder you'll find a text file with a variety of vendor specific keys with both code and Slack message contexts. 

If a key status is marked as ‘Active’, please rotate the key immediately. Not all vendors provide an "Inactive" response code. In these cases or if the vendor service is offline, the finding status will be marked ‘Unverified’.

## Negative Samples

In this folder, you'll find actual code samples are pulled from open source GitHub repos, not contrived test cases. Each snippet contains strings that match vendor-specific API key regex.

Nightfall's NLP-based detector recognizes these as valid negatives, not secrets
