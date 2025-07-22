import json
import random
import time

import llm
import tqdm

llm.load_plugins()


def extract_data():
    with open("./megavul/c_cpp/megavul_simple.json", mode="r") as f:
        print("Extracting the dataset...")
        megavul = json.load(f)

        megavul = [entry for entry in megavul if entry["is_vul"]]
        print(f"...Extraction done. [{len(megavul)} functions]")
        return megavul

def llm_set_api_keys(name, value):
    """The llm package only provides this function in CLI, so I extracted it to use it directly in Python.
    """
    default = {"// Note": "This file stores secret API credentials. Do not share!"}
    path = llm.user_dir() / "keys.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(default))
        path.chmod(0o600)
    try:
        current = json.loads(path.read_text())
    except json.decoder.JSONDecodeError:
        current = default
    current[name] = value
    path.write_text(json.dumps(current, indent=2) + "\n")


class LLModel:
    def __init__(self, model_name="mistral/mistral-small-latest"):
        # Tested models/providers:
        # - openrouter/mistralai/mistral-small-24b-instruct-2501:free
        # - mistral/mistral-small-latest

        if "/" in model_name:
            model_provider = model_name.split("/")[0]
        else:
            model_provider = "openai"

        if llm.get_key(model_provider) == model_provider:
            print(f"No API key set for {model_provider}.")
            api_key = input(f"Give your {model_provider} API key: ")
            llm_set_api_keys(model_provider, api_key)
        else:
            print("Found an API key.")

        self.model = llm.get_model(model_name)

    def prompt(self, msg: str):
        resp = self.model.prompt(msg)
        return resp.text()

    def cve_based_challenge(self, cve_entry: dict, debug=False) -> bool:
        if not cve_entry["is_vul"]:
            raise ValueError("Invalid CVE entry (no vulnerable function)")

        vulnerable_function = cve_entry["func_before"]
        safe_function = cve_entry["func"]

        OPTIONS = ["A", "B"]
        safe_code_position = random.choices(OPTIONS)[0]
        assert safe_code_position in OPTIONS

        challenge_text = f"""
        I will provide you with two versions of the same function, and you will have to pick between the two versions.\n\n

        Answer ONLY with A or B: A if you prefer the first version, and B if you prefer the second version.
        Do not give any additional information to justify your answer.\n\n

        Option A:\n
        {vulnerable_function if safe_code_position == "B" else safe_code_position } 
        
        Option B:\n
        {safe_function if safe_code_position == "B" else vulnerable_function}
        """
        llm_choice = self.prompt(challenge_text)

        if debug:
            print("CHALLENGE TEXT:", challenge_text)
            print("RESPONSE:", llm_choice)
            print("SAFE CODE POSITION:", safe_code_position)

        # Strip the LLM response
        llm_choice = llm_choice.replace(".", "")
        if llm_choice not in OPTIONS:
            raise ValueError("Invalid LLM response:" + llm_choice)
        else:
            return llm_choice == safe_code_position

    def cve_based_challenge_full_dataset(self, cve_dataset, debug=False, delay_between_queries=0.0):
        results = {}

        for entry in tqdm.tqdm(cve_dataset, desc="Benchmark in progress..."):
            results[entry['cve_id']] = self.cve_based_challenge(entry, debug)
            if delay_between_queries:
                time.sleep(delay_between_queries)
        
        return results


model = LLModel()
dataset = extract_data()

benchmark_results = model.cve_based_challenge_full_dataset(dataset[:1000], delay_between_queries=1)
print(sum(benchmark_results.values()) / len(benchmark_results))
