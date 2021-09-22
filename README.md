# oac_dbsec_posture

Checks for Oracle Analytics Cloud instances in all regions and compartments for a tenancy and provides security posture info 

Installation

Download the python script: wget https://raw.githubusercontent.com/chad-russell-git/oac_dbsec_posture/main/oac_dbsec_posture_v1.py

Create a virtual environment: python3 -m venv oci_scripts_venv

Source the environment: source oci_scripts_venv/bin/activate

Install the dependences: pip3 install oci

Running the script on a local machine

Source the environment: source oci_scripts_venv/bin/activate

Run the script: python3 oac_dbsec_posture_v1.py

Running the script in Cloud Shell

Source the environment: source oci_scripts_venv/bin/activate

Run the script: python3 oac_dbsec_posture_v1.py -dt
