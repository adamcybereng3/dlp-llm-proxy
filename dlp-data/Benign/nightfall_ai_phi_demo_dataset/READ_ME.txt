# Sample Dataset for Testing PHI Detection

This sample dataset demonstrates Nightfall's advanced protected health information (PHI) detection capabilities. The data has been fully de-identified and can be used to test PHI detection on any data loss prevention (DLP) platform.

## What is PHI?

PHI refers to specific combinations of personally identifiable information (PII) that can uniquely identify an individual patient and health indicators that disclose patient conditions. 

For example, a document containing a patient's name, address, and diagnosis constitutes PHI = Lisa Samson + 2310 Maple Ave SF, CA 94106 + Cancer diagnosis

PHI exposure occurs when this type of information is inappropriately disclosed. 

## Challenges with Legacy DLP Systems

Many legacy DLP systems rely on individual detectors to try to detect PHI leakage. However, this approach has several drawbacks:

**1. Complex Setup** - Detecting PHI requires scanning for numerous combinations of PII and health indicators.

PII (data required to uniquely identify an individual)
- Person name + date of birth
- Person name + street address
- US Social Security Number
- Medical Beneficiary identifier
- VIN
- phone number
- email address
	
Health indicators (data associated with a medical condition)
- Diagnosis 
- Diagnostic code (ICD)
- Doctor ID number (National Provider ID)
- Drug name
- Drug code
- Procedure

**2. Error Propagation** - Using many detectors in combination is only as accurate as the weakest detector. Noisy individual detectors lead to noisy overall results.

**3. Lack of Context** - Individual detectors do not understand semantic relationships between entities or the overall intent of a document. This leads to false positives.

For example, a legacy system might trigger false PHI alerts by detecting names + an address + the term "Cancer"  in meeting notes about a new parking lot construction project at a Cancer clinic.

legacy system DLP PHI detection = 
	names (of attendees) 
	+ street address (of either the mtg or parking lot or both) 
	+ a diagnosis ("Cancer" Center) 

## Advanced PHI Detection

This sample dataset demonstrates advanced PHI detection capabilities that address the challenges above by:

- Understanding the contextual intent of documents before analyzing PHI components
- Identifying patient relationships within documents
- Providing accurate results without extensive configuration

Please use this de-identified data to test advanced PHI detection capabilities.