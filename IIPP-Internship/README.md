
# IIPP INTERNSHIP

This repo covers all the work I have done as a Research Intern during my IIPP internship at National Yang Ming Chiao Tung University, Tainan under the guidance of Professor Ren-Hung Hwang at the [AINT Lab](https://aint.lab.nycu.edu.tw/students)


# Hi, I'm Pavan! 👋

I'm a final year student pursuring Btech Computer Science with specialization in Cyber Security.
## Internship Goals
- Month 1: Orientation and Goal Selection
    - Introduction to MITRE Engage Framework
    - Goal selection
- Month 2: Proposal and Planning
    - Propose actions to implement in Honeypot
    - Plan my techniques to implement MITRE ENGAGE into the Honeypot 
- Month 3: Implementation and Documentation
    - Implementing the actions into the two honeypots: SSH honeypot and AD honeypot.
    - Documentation of our work


## [MITRE ENGAGE](https://github.com/Lonelypheonix/IIPP-Internship/tree/main/1.%20MITRE%20ENGAGE)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://engage.mitre.org/starter-kit/)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://engage.mitre.org/)
\
MITRE Engage is a framework
- for planning and discussing adversary engagement operations
- that empowers you to engage your adversaries
- and achieve your cybersecurity goals.

There are three goals under MITRE ENGAGE (Expose, Affect, and Elicit) \
After reading the documentation and researching about MITRE ENGAGE, I choose the ELICIT goal and my internship goal was to implement the actions listed under each goal in the two HoneyPots SSH honeypot and AD honeypot.

### Elicit goal
Learn about adversaries tactics, techniques, and procedures (TTPs).
Engage defines two approaches to make progress towards the Elicit goal.

- Reassurance focuses on providing an environment that reduces adversary suspicion by meeting expectations and creating an artifact rich environment.
- Motivation seeks to create a target rich environment that encourages the adversary to engage in new TTPs.




## [CALDERA](https://github.com/Lonelypheonix/IIPP-Internship/tree/main/2.%20Caldera)

[![Documentation Status](https://readthedocs.org/projects/caldera/badge/?version=stable)](http://caldera.readthedocs.io/?badge=stable)

MITRE Caldera is a cyber security platform designed to easily automate adversary emulation, assist manual red-teams, and automate incident response.
It is built on the [MITRE ATT&CK™ framework](https://attack.mitre.org/)

| Caldera Login                       |
| ----------------------------------- |
| ![Caldera Logo](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/2.%20Caldera/Caldera%20screenshots/Caldera-logo.png) |

clone the repository from the offical github repository

```bash
  git clone https://github.com/mitre/caldera.git --recursive
  cd caldera
```
install the pip requirements and start the server 
```bash
  sudo pip3 install -r requirements.txt
  python3 server.py
```
Once started, log in to http://localhost:8888 with the red using the password found in the conf/local.yml file 

| Caldera Login                       |
| ----------------------------------- |
| ![Caldera Login](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/2.%20Caldera/Caldera%20screenshots/Caldera%20dashboard.png) | 

| Caldera dashboard                   |
| ----------------------------------- |
| ![Caldera dashboard](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/2.%20Caldera/Caldera%20screenshots/Agents%20active.png) |


## [Wazuh](https://github.com/Lonelypheonix/IIPP-Internship/tree/main/3.%20Wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
- Wazuh is open-source, freely available extensive EDR and HIDS (Host-Based Intrusion Detection System) solution.
- Along with the collection of data, Wazuh offers an Incident Response system based on events.
- Wazuh makes use of Sysmon as well as Osquery to get different information about the host.

install Wazuh 
```bash
  curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && Sudo bash ./wazuh-install.sh -a 
```
You will get the username and password at the end of installation. We can access the Wazuh dashboard at http://localhost:443 login using the credentials.


| Wazuh Login                        |
| -----------------------------------|
| ![Wazuh Login](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/3.%20Wazuh/Wazuh%20screenshots/wauzh%20login%20page.png) |

| Wazuh dashboard                     |
| ----------------------------------- |
| ![wazuh dashboard](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/3.%20Wazuh/Wazuh%20screenshots/wazuh%20dashboard.png) |


Once the dashboard is ready, Configure Wazuh agenst at your endpoints using the wazuh agent module.

| Wazuh Agent                        |
| -----------------------------------|
| ![Wazuh Agent](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/3.%20Wazuh/Wazuh%20screenshots/wazuh%20agent%20deploy.png) |

| Wazuh Agent install                 |
| ----------------------------------- |
| ![wazuh Agent install](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/3.%20Wazuh/Wazuh%20screenshots/agent%20code%20at%20endpoint.png) |


## [Cowrie](https://github.com/Lonelypheonix/IIPP-Internship/tree/main/4.%20Cowrie%20Honeypot)

Cowrie is a medium to high interaction SSH and Telnet honeypot designed to log brute force attacks and the shell interaction performed by the attacker. In medium interaction mode (shell) it emulates a UNIX system in Python, in high interaction mode (proxy) it functions as an SSH and telnet proxy to observe attacker behaviour to another system.

| Cowrie Logo                         |
| ----------------------------------- |
| ![Cowrie Logo](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/4.%20Cowrie%20Honeypot/Cowrie%20screenshots/cowrie%20logo.png) |

Install system dependencies :
```bash
  sudo apt-get install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv
```
Create a user account :
```bash
  sudo adduser --disabled-password cowrie
  sudo su - cowrie
```
clone the repository from the offical github repository :

```bash
  git clone http://github.com/cowrie/cowrie
  cd cowrie
```
Setup Virtual Environment  :
```bash
  python -m venv cowrie-env
  source cowrie-env/bin/activate
```
install the pip requirements and start cowrie :
```bash
  python -m pip install --upgrade -r requirements.txt
  bin/cowrie start
```
Listening on port 22 :
```bash
  sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
  sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
  sudo apt-get install authbind
  sudo touch /etc/authbind/byport/22
  sudo chown cowrie:cowrie /etc/authbind/byport/22
  sudo chmod 770 /etc/authbind/byport/22

```
Once started, log in to http://localhost:8888 with the red using the password found in the conf/local.yml file 
| Start Cowrie                        |
| ----------------------------------- |
| ![Start Cowrie](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/4.%20Cowrie%20Honeypot/Cowrie%20screenshots/Start%20cowrie.png) | 

| Cowrie Logs                         |
| ----------------------------------- |
| ![cowrie Logs](https://github.com/Lonelypheonix/IIPP-Internship/blob/main/4.%20Cowrie%20Honeypot/Cowrie%20screenshots/coriew%20log%20file.png) |

## Documentation

- [MITRE ENGAGE](https://engage.mitre.org/starter-kit/)
- [Caldera](https://caldera.readthedocs.io/en/latest/)
- [Wazuh](https://documentation.wazuh.com/current/getting-started/index.html)
- [Cowrie](https://cowrie.readthedocs.io/en/latest/index.html)
- [Active directory](https://linktodocumentation)
- [Suricata](https://docs.suricata.io/en/latest/)
## Feedback

If you have any feedback, please reach out to me at pavankumarj.cy@gmail.com



## Acknowledgements
Special thanks to my Lab seniors 
 - Howard [@haward79](https://github.com/haward79) : (haward79@yahoo.com.tw)
- Chin Pan : (c45678982@gmail.com)
- Hsin Lin : (s1999881207@gmail.com)
- Wei-Ting Chang : (c10016338@gmail.com) \
  And Professor Ren-Hung Hwang for his valuable guidance.
