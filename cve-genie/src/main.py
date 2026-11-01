import os
import time
import signal
import argparse
from dotenv import load_dotenv

class TimeoutExpired(Exception):
    def __init__(self, phase: str = None, message: str = "Timeout expired"):
        self.phase = phase
        self.message = f"{message} during phase: {phase}" if phase else message
        super().__init__(self.message)

def alarm_handler(signum, frame):
    raise TimeoutExpired

if not os.environ.get('ENV_PATH'):
    load_dotenv()
else:
    dotenv_path = os.environ['ENV_PATH']
    load_dotenv(dotenv_path=dotenv_path)

if not os.environ.get('MODEL'):
    exit(1)

MODEL = os.environ['MODEL']

from toolbox import helper, CVEDataProcessor, Validator
from agents import KnowledgeBuilder, PreReqBuilder, RepoBuilder, RepoCritic, Exploiter, ExploitCritic, CTFVerifier, SanityGuy

KB = False
PRE_REQ = False
REPO = False
REPO_CRITIC = False

EXPLOIT = False
EXPLOIT_CRITIC = False

CTF_VERIFIER = False
SANITY_CHECK = False

TIMEOUT = 2700
MAX_COST = 5.00

class CVEReproducer:
    def __init__(self, cve_id: str, cve_json: str):
        self.cve_id = cve_id
        self.cve_json = cve_json
        self.total_cost = 0
        self.results = {}
        self.start_time = None
    
    def check_time(self, phase: str = None):
        if time.time() - self.start_time > TIMEOUT:
            raise TimeoutExpired(phase=phase)

    def update_cost(self, cost: float, exception: bool = False):
        self.total_cost += cost
        if self.total_cost >= MAX_COST and not exception:
            raise ValueError("Cost exceeds maximum limit")

    def run(self):
        try:
            if KB:
                print(f"\n🛠️ Reproducing {self.cve_id} ...")

                print("🤖 Model: ", MODEL)

                print("\n########################################\n" \
                    "# 1) 📚 Running CVE Processor ...\n" \
                    "########################################\n")
                
                print("\n----------------------------------------\n" \
                    "- a) 📋 CVE Data Processor \n" \
                    "-------------------------------------------\n")
                processor = CVEDataProcessor(self.cve_id, self.cve_json)
                self.cve_info = processor.run()
                helper.save_response(self.cve_id, self.cve_info, "cve_info", struct=True)

                print(f"✅ CVE Data Processor Done!")

                print("\n⏰ Starting timer ...")
                self.start_time = time.time()
                
                print("\n----------------------------------------\n" \
                    "- a) 🧠 Knowledge Builder \n" \
                    "-------------------------------------------\n")
        
                cwe = '\n'.join([f"* {c['id']} - {c['value']}" for c in self.cve_info["cwes"]]) if "cwes" in self.cve_info else ""
                project_name = self.cve_info["sw_version_wget"].split("//")[1].split("/")[2]
                patches = '\n\n'.join([f"Commit Hash: {p['url'].split('/')[-1]}\n\"\"\"\n{p['content']}\n\"\"\"" for p in self.cve_info["patch_commits"]]) if "patch_commits" in self.cve_info else ""
                sec_adv = '\n\n'.join([f"Advisory: {a['url']}\n\"\"\"\n{a['content']}\n\"\"\"" for ix, a in enumerate(self.cve_info["sec_adv"])]) if "sec_adv" in self.cve_info else ""
                knowledge_builder = KnowledgeBuilder(
                    id = self.cve_id,
                    description = self.cve_info["description"],
                    cwe = cwe,
                    project_name = project_name,
                    affected_version = self.cve_info["sw_version"],
                    security_advisory = sec_adv,
                    patch = patches
                )
                res = knowledge_builder.invoke().value
                print(f"⛺️ Knowledge Base: '''\n{res}\n'''")
                helper.save_response(self.cve_id, res, "knowledge_builder")
                self.update_cost(knowledge_builder.get_cost())
                print(f"✅ Knowledge Builder Done!")
            else:
                try:
                    res = helper.load_response(self.cve_id, "knowledge_builder")
                    self.cve_info = helper.load_response(self.cve_id, "cve_info", struct=True)
                except FileNotFoundError:
                    print("❌ Knowledge Builder response not found!")
                    self.results = {"success": "False", "reason": "Knowledge Builder response not found"}
                    return
            self.cve_knowledge = res

            print(f"\n💰 Cost till Knowledge Builder = {self.total_cost}\n")

            if PRE_REQ:
                
                print("\n########################################\n" \
                    "# 2) 🛠️ Running Project Builder ...\n" \
                    "########################################\n")

                print("\n----------------------------------------\n" \
                    "- a) 📋 Pre-Requsites Builder \n" \
                    "-------------------------------------------\n")

                pre_req_builder = PreReqBuilder(
                    cve_knowledge = self.cve_knowledge,
                    project_dir_tree = self.cve_info['dir_tree']
                )
                res = pre_req_builder.invoke().value
                helper.save_response(self.cve_id, res, "pre_req_builder", struct=True)
                self.update_cost(pre_req_builder.get_cost())
                print(f"✅ Pre-Requsites Builder Done!")
            else:
                try:
                    res = helper.load_response(self.cve_id, "pre_req_builder", struct=True)
                except FileNotFoundError:
                    print("❌ Pre-Requsites Builder response not found!")
                    self.results = {"success": "False", "reason": "Pre-Requsites Builder response not found"}
                    return
            self.pre_reqs = res

            print(f"\n💰 Cost till Pre-Req = {self.total_cost}\n")

            if REPO:
                print("\n----------------------------------------\n" \
                    "- b) 🏭 Repository Builder \n" \
                    "-------------------------------------------\n")
                
                repo_done = False
                repo_feedback, critic_feedback = None, None
                repo_try, critic_try = 1, 1
                max_repo_tries, max_critic_tries = 3, 2

                while not repo_done and repo_try <= max_repo_tries and critic_try <= max_critic_tries:
                    self.check_time("project_build")
                    if repo_feedback or critic_feedback:
                        print("\n----------------------------------------\n" \
                            "- b) 🎯 Feedback-Based Repository Builder \n" \
                            "-------------------------------------------\n")
                    
                    repo_builder = RepoBuilder(
                        project_dir_tree = self.cve_info['dir_tree'],
                        cve_knowledge = self.cve_knowledge,
                        build_pre_reqs = self.pre_reqs,
                        feedback = repo_feedback,
                        critic_feedback = critic_feedback
                    )
                    res = repo_builder.invoke().value
                    critic_feedback = None # Reset critic feedback for next iteration

                    # Check if the agent stopped due to max iterations
                    if res == "Agent stopped due to max iterations.":
                        print("🛑 Repo Builder stopped due to max iterations!")
                        if repo_try < max_repo_tries:
                            print("📋 Summarizing work ...")
                            repo_builder.__OUTPUT_PARSER__ = None
                            res = repo_builder.invoke(dict(
                                ERROR = "You were not able to perform the task in the given maximum number of tool calls. Now summarize in detail the steps you took to solve the task, such that another agent could pick up where you left off. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                            ))
                            repo_feedback = res.value
                            critic_feedback = None

                        self.update_cost(repo_builder.get_cost())
                    else:
                        self.repo_build = res

                        # ----- Save the repo build response -----
                        setup_logs = helper.parse_chat_messages(repo_builder.chat_history, include_human=True)
                        setup_logs = helper.remove_tree_from_setup_logs(setup_logs)
                        helper.save_response(self.cve_id, setup_logs, f"repo_builder_setup_logs")
                        print(f"📜 Setup Logs:\n'''\n{setup_logs}\n'''")

                        if self.repo_build['success'].lower() == "yes":
                            if REPO_CRITIC:
                                # ----- Invoke Critic for repo build -----
                                print("\n----------------------------------------\n" \
                                        "👀 Running Critic on Repo Builder ...\n" \
                                        "-------------------------------------------\n")
                                critic = RepoCritic(
                                    setup_logs = setup_logs
                                )
                                res = critic.invoke().value
                                helper.save_response(self.cve_id, res, "repo_critic", struct=True)
                                critic_try += 1

                                if res['decision'].lower() == 'no':
                                    print("❌ Critic rejected the repo build!")

                                    if res['possible'].lower() == 'no':
                                        print("🚨 It is not possible to correct the setup!!")
                                        self.results = {"success": "False", "reason": 'Not possible to build the repo!!!'}
                                        self.update_cost(repo_builder.get_cost())
                                        return
                                    
                                    if not res['feedback'].strip():
                                        print("🚨 No Feedback!!")
                                        self.results = {"success": "False", "reason": 'No feedback to correct the setup!!!'}
                                        self.update_cost(repo_builder.get_cost())
                                        return

                                    print("📋 Sending feedback to repo builder!")
                                    critic_feedback = res['feedback']
                                    repo_feedback = None # Reset repo feedback for critic iteration
                                    repo_try = 0
                                else:
                                    print("✅ Critic accepted the repo build!")
                                    # ------------------------------------------
                                    repo_done = True
                                    self.repo_build['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                    helper.save_response(self.cve_id, self.repo_build, "repo_builder", struct=True)
                                    print(f"✅ Repo Builder Done!")
                                self.update_cost(critic.get_cost(), exception=repo_done)
                            else:
                                repo_done = True
                                self.repo_build['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                helper.save_response(self.cve_id, self.repo_build, "repo_builder", struct=True)
                                print(f"✅ Repo Builder Done!")
                        else:
                            if repo_try < max_repo_tries:
                                print("❌ Repo could not be built!")
                                print("📋 Sending output feedback to Repo Builder ...")
                                repo_builder.__OUTPUT_PARSER__ = None
                                res = repo_builder.invoke(dict(
                                    ERROR = "As you were not able to build the repository, summarize in detail the steps you took to build the repository, such that an expert could take a look at it and try to resolve it. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                                ))
                                repo_feedback = res.value
                                critic_feedback = None
                            else:
                                print("❌ Repo agent gave up!")
                        self.update_cost(repo_builder.get_cost(), exception=repo_done)
                    repo_try += 1

                if not repo_done:
                    print("❌ Repo could not be built!")
                    helper.save_response(self.cve_id, {"success": "no", "access": "Repo could not be built after all tries", "time_left": 1}, "repo_builder", struct=True)
                    self.results = {"success": "False", "reason": "Repo could not be built"}
                    return
                else:
                    print("✅ Repo Built Successfully!")
            else:
                try:
                    res = helper.load_response(self.cve_id, "repo_builder", struct=True)
                except FileNotFoundError:
                    print("❌ Repo Builder response not found!")
                    self.results = {"success": "False", "reason": "Repo Builder response not found"}
                    return
                self.repo_build = res

            print(f"\n💰 Cost till Repo Builder = {self.total_cost}\n")

            if self.repo_build['success'].lower()=="no":
                self.results = {"success": "False", "reason": 'Repo was not built!!!'}
                return

            if EXPLOIT:
                os.environ['REPO_PATH'] = self.cve_info['repo_path']
                
                print("Time left: ", self.repo_build['time_left'])
                
                print("\n########################################\n" \
                    "# 6) 🚀 Running Exploiter ...\n" \
                    "########################################\n")
                
                exploit_done = False
                exploit_feedback, exploit_critic_feedback = None, None
                exploit_try, exploit_critic_try = 1, 1
                max_exploit_tries, max_exploit_critic_tries = 3, 2

                while not exploit_done and exploit_try <= max_exploit_tries and exploit_critic_try <= max_exploit_critic_tries:
                    self.check_time("exploit_build")
                    if exploit_feedback or exploit_critic_feedback:
                        print("\n----------------------------------------\n" \
                            "- a) 🧨 Feedback-Based Exploiter \n" \
                            "-------------------------------------------\n")
                    exploiter = Exploiter(
                        cve_knowledge = self.cve_knowledge,
                        project_overview = self.pre_reqs['overview'],
                        project_dir_tree = self.cve_info['dir_tree'],
                        repo_build = self.repo_build,
                        feedback = exploit_feedback,
                        critic_feedback = exploit_critic_feedback
                    )
                    res = exploiter.invoke().value

                    # Check if the agent stopped due to max iterations
                    if res == "Agent stopped due to max iterations.":
                        print("🛑 Exploiter stopped due to max iterations!")
                        if exploit_try < max_exploit_tries:
                            print("📋 Summarizing work ...")
                            exploiter.__OUTPUT_PARSER__ = None
                            res = exploiter.invoke(dict(
                                ERROR = "You were not able to perform the task in the given maximum number of tool calls. Now summarize in detail the steps you took to solve the task, such that another agent could pick up where you left off. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                            ))
                            exploit_feedback = res.value
                            exploit_critic_feedback = None
                        
                        self.update_cost(exploiter.get_cost())
                    else:
                        self.exploit = res

                        # ---- Save the exploit response ----
                        exploit_logs = helper.parse_chat_messages(exploiter.chat_history, include_human=True)
                        exploit_logs = helper.remove_tree_from_exploit_logs(exploit_logs)
                        helper.save_response(self.cve_id, exploit_logs, f"exploiter_logs")
                        print(f"📜 Exploit Logs:\n'''\n{exploit_logs}\n'''")

                        if self.exploit['success'].lower() == "yes":
                            if EXPLOIT_CRITIC:
                                # ----- Invoke Critic for exploit -----
                                print("\n----------------------------------------\n" \
                                        "👀 Running Critic on Exploiter ...\n" \
                                        "-------------------------------------------\n")
                                critic = ExploitCritic(
                                    exploit_logs = exploit_logs
                                )
                                res = critic.invoke().value
                                helper.save_response(self.cve_id, res, "exploit_critic", struct=True)
                                exploit_critic_try += 1

                                if res['decision'].lower() == 'no':
                                    print("❌ Critic rejected the exploit!")

                                    if res['possible'].lower() == 'no':
                                        print("🚨 It is not possible to exploit the vulnerability!!")
                                        self.results = {"success": "False", "reason": 'Not possible to exploit the vulnerability!!!'}
                                        return
                                    
                                    if not res['feedback'].strip():
                                        print("🚨 No Feedback!!")
                                        self.results = {"success": "False", "reason": 'No feedback to correct the exploit!!!'}
                                        return

                                    print("📋 Sending feedback to exploiter!")
                                    exploit_critic_feedback = res['feedback']
                                    exploit_feedback = None # Reset exploit feedback for critic iteration
                                    exploit_try = 0
                                else:
                                    print("✅ Critic accepted the exploit!")
                                    # ------------------------------------------
                                    exploit_done = True
                                    self.exploit['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                    helper.save_response(self.cve_id, self.exploit, "exploiter", struct=True)
                                    print(f"✅ Exploiter Done!")
                                self.update_cost(critic.get_cost(), exception=exploit_done)
                            else:
                                exploit_done = True
                                self.exploit['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                helper.save_response(self.cve_id, self.exploit, "exploiter", struct=True)
                                print(f"✅ Exploiter Done!")
                        else:
                            if exploit_try < max_exploit_tries:
                                print("❌ Exploiter failed!")
                                print("📋 Sending output feedback to Exploiter ...")
                                exploiter.__OUTPUT_PARSER__ = None
                                res = exploiter.invoke(dict(
                                    ERROR = "As you were not able to exploit the vulnerability, summarize in detail the steps you took to exploit the vulnerability, such that an expert could take a look at it and try to resolve it. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                                ))
                                exploit_feedback = res.value
                                exploit_critic_feedback = None
                            else:
                                print("❌ Exploiter gave up!")
                        self.update_cost(exploiter.get_cost(), exception=exploit_done)
                    exploit_try += 1
                
                if not exploit_done:
                    print("❌ Exploiter failed!")
                    helper.save_response(self.cve_id, {"success": "no", "reason": "Exploiter failed"}, "exploiter", struct=True)
                    self.results = {"success": "False", "reason": "Exploiter failed"}
                    return
                else:
                    helper.create_exploit_script(self.exploit['poc'])
                    print("✅ Exploit Script Created!")
                    self.results = {"success": "True", "reason": "Exploit script created"}
            else:
                try:
                    res = helper.load_response(self.cve_id, "exploiter", struct=True)
                except FileNotFoundError:
                    print("❌ Exploiter response not found!")
                    self.results = {"success": "False", "reason": "Exploiter response not found"}
                    return
                self.exploit = res

            print(f"\n💰 Cost till Exploiter = {self.total_cost}\n")

            if self.exploit['success'].lower() == "no":
                self.results = {"success": "False", "reason": 'Exploit was not generated!!!'}
                return
            
            if CTF_VERIFIER:
                os.environ['REPO_PATH'] = self.cve_info['repo_path']

                print("Time left: ", self.exploit['time_left'])
                
                print("\n########################################\n" \
                    "- b) 🛡️ CTF Verifier \n" \
                    "########################################\n")
                
                verifier_done = False
                try_itr, sanity_itr = 1, 1
                max_flag_tries, max_sanity_tries = 5, 5
                ctf_feedback = None

                while not verifier_done and try_itr <= max_flag_tries and sanity_itr <= max_sanity_tries:
                    self.check_time("verifier_build")

                    if ctf_feedback:
                        print("\n----------------------------------------\n" \
                            "- b) 🛡️ Feedback-Based CTF Verifier \n" \
                            "-------------------------------------------\n")
                
                    ctf_verifier = CTFVerifier(
                        project_dir_tree = self.cve_info['dir_tree'],
                        cve_knowledge = self.cve_knowledge,
                        project_overview = self.pre_reqs['overview'],
                        repo_build = self.repo_build,
                        exploit = self.exploit,
                        feedback = ctf_feedback
                    )
                    res = ctf_verifier.invoke().value
                    self.ctf_verifier = res
                    helper.save_response(self.cve_id, self.ctf_verifier, "ctf_verifier", struct=True)
                    print(f"✅ CTF Verifier Done!")

                    print("\n----------------------------------------\n" \
                        "- c) 🎯 Validator \n" \
                        "-------------------------------------------\n")

                    validator = Validator(
                        verifier = self.ctf_verifier['verifier']
                    )
                    check, val_log = validator.validate()

                    if check:
                        print("🎯 Flag found!")

                        if SANITY_CHECK:
                            print("\n----------------------------------------\n" \
                                "- d) 🧼 Verifier Critic Agent\n" \
                                "-------------------------------------------\n")
                            sanity_guy = SanityGuy(
                                cve_knowledge = self.cve_knowledge,
                                project_access = self.repo_build['access'],
                                exploit = self.exploit['exploit'],
                                poc = self.exploit['poc'],
                                verifier = self.ctf_verifier['verifier'],
                                validator_logs = val_log
                            )
                            sanity_guy_res = sanity_guy.invoke().value
                            helper.save_response(self.cve_id, sanity_guy_res, "verifier_critic", struct=True)
                            sanity_itr += 1

                            if sanity_guy_res['decision'].lower() == "no":
                                print("❌ Critic rejected the verifier!")

                                if not sanity_guy_res['steps_to_fix']:
                                    print("🚨 No Feedback!!")
                                    self.results = {"success": "False", "reason": 'No feedback to correct the verifier!!!'}
                                    return
                                
                                print("📋 Sending feedback to CTF Verifier!")
                                ctf_feedback = f"Previous Code: ```\n{self.ctf_verifier['verifier']}\n```\n\nProposed Fixes: '''\n{sanity_guy_res['steps_to_fix']}\n'''"
                                try_itr = 0
                            else:
                                verifier_done = True
                                helper.save_response(self.cve_id, self.ctf_verifier, "ctf_verifier", struct=True)
                                print("✅ Critic accepted the verifier!")
                            self.update_cost(sanity_guy.get_cost(), exception=True)
                        else:
                            verifier_done = True
                            helper.save_response(self.cve_id, self.ctf_verifier, "ctf_verifier", struct=True)
                            print("✅ CTF Verifier Done!")
                    else:
                        print("❌ Flag not found!")
                        print("📋 Sending output feedback to CTF Verifier ...")
                        ctf_feedback = f"Previous Code: ```\n{self.ctf_verifier['verifier']}\n```\n\nOutput Logs: '''\n{validator.feedback}\n'''"
                    try_itr += 1
                    self.update_cost(ctf_verifier.get_cost(), exception=True)
                        
                if not verifier_done:
                    print("❌ CTF Verifier failed!")
                    helper.save_response(self.cve_id, {"success": "no", "reason": "CTF Verifier failed"}, "ctf_verifier", struct=True)
                    self.results = {"success": "False", "reason": "CTF Verifier failed"}
                    return
                else:
                    print("✅ CTF Verifier Done!")
                    helper.save_ctf_script(self.cve_id, self.ctf_verifier['verifier'], self.exploit['poc'])
                    self.results = {"success": "True", "reason": "CTF Verifier done! CVE reproduced!"}

        except TimeoutExpired as e:
            print(f"ERROR: {e.message}")
            self.results = {"success": "False", "reason": e.message}
            raise

        except Exception as e:
            print(f"ERROR: {str(e)}")
            self.results = {"success": "False", "reason": str(e)}
        
        finally:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reproduce a CVE")
    parser.add_argument(
        "--cve",
        type=str,
        required=True,
        help="CVE ID",
        default='CVE-2024-4340'
    )
    parser.add_argument(
        "--json",
        type=str,
        required=True,
        help="Path to the cve json file",
        default='dummy_data/data.json'
    )
    parser.add_argument(
        "--run-type",
        type=str,
        required=True,
        choices=['build', 'exploit', 'verify', 'build,exploit', 'exploit,verify', 'build,exploit,verify'],
        help="Type of run: build, exploit, verify",
        default='build,exploit,verify'
    )
    args = parser.parse_args()

    run_types = args.run_type.split(',')

    if 'build' in run_types:
        KB = True
        PRE_REQ = True
        REPO = True
        REPO_CRITIC = True
    if 'exploit' in run_types:
        EXPLOIT = True
        EXPLOIT_CRITIC = True
    if 'verify' in run_types:
        CTF_VERIFIER = True
        SANITY_CHECK = True

    reproducer = CVEReproducer(args.cve, args.json)
    
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(TIMEOUT)
    
    try:
        reproducer.run()
    except:
        signal.alarm(0)
    
    print("Cost:", reproducer.total_cost)
    reproducer.results['cost'] = reproducer.total_cost
    reproducer.results['time'] = TIMEOUT - signal.alarm(0)
    reproducer.results['model'] = os.environ['MODEL']
    print("Results:", reproducer.results)
    helper.save_result(args.cve, reproducer.results)
