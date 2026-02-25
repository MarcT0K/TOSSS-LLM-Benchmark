import csv
import json
import logging
import os
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

import llm
import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

llm.load_plugins()

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class RateLimiter:
    """Simple rate limiter to manage API calls per minute."""

    def __init__(self, requests_per_minute=30):
        self.requests_per_minute = requests_per_minute
        self.request_times = []
        self.min_delay = 60.0 / requests_per_minute if requests_per_minute > 0 else 0

    def wait_if_needed(self):
        now = datetime.now()

        cutoff = now - timedelta(minutes=1)
        self.request_times = [t for t in self.request_times if t > cutoff]

        # If we've hit the rate limit, wait
        if len(self.request_times) >= self.requests_per_minute:
            sleep_time = (
                self.request_times[0] + timedelta(minutes=1) - now
            ).total_seconds()
            if sleep_time > 0:
                logging.info(f"Rate limit reached. Waiting {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)

        # Add current request time
        self.request_times.append(now)

        # Ensure minimum delay between requests
        if len(self.request_times) > 1 and self.min_delay > 0:
            time_since_last = (now - self.request_times[-2]).total_seconds()
            if time_since_last < self.min_delay:
                additional_wait = self.min_delay - time_since_last
                time.sleep(additional_wait)


def extract_data(dataset):
    logging.info(f"Extracting the dataset from {dataset}...")

    with open(dataset, encoding="utf-8", mode="r") as f:
        megavul = json.load(f)
        megavul = [entry for entry in megavul if entry["is_vul"]]

    logging.info(f"...Extraction done. [{len(megavul)} functions]")
    return megavul


def llm_set_api_keys(name, value):
    """The llm package only provides this function in CLI, so I extracted it to use it directly in Python."""
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
    def __init__(self, model_name="mistral/codestral-2501", rate_limiter=None):
        # Tested models/providers:
        # - openrouter/mistralai/mistral-small-24b-instruct-2501:free
        # - mistral/mistral-small-latest
        # - mistral/mistral-large-latest

        self.model_name = model_name
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
        self.rate_limiter = rate_limiter

    def prompt(self, msg: str):
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
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
        I will provide you with two versions of the same function, and you will have to select one between the two versions.\n\n

        Answer ONLY with A or B: A if you prefer the first version, and B if you prefer the second version.
        Do not give any additional information to justify your answer.\n\n

        Option A:\n
        {vulnerable_function if safe_code_position == "B" else safe_function}

        Option B:\n
        {safe_function if safe_code_position == "B" else vulnerable_function}
        """
        llm_choice = self.prompt(challenge_text)

        if debug:
            logging.info(f"CHALLENGE TEXT: {challenge_text}")
            logging.info(f"RESPONSE: {llm_choice}")
            logging.info(f"SAFE CODE POSITION: {safe_code_position}")

        # Strip the LLM response
        llm_choice = llm_choice.replace(".", "")
        if llm_choice not in OPTIONS:
            raise ValueError("Invalid LLM response:" + llm_choice)
        else:
            return llm_choice == safe_code_position

    def load_existing_results(self, csv_filename):
        """Load existing results from CSV file to resume where we left off."""
        if not os.path.exists(csv_filename):
            return {}, 0

        results = {}
        completed_count = 0
        try:
            with open(csv_filename, mode="r", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row["cve_id"] and row["success"]:  # Skip empty rows
                        cve_id = row["cve_id"]
                        success = row["success"].lower() == "true"
                        completed_count += 1

                        # For duplicates, we'll use the last result seen
                        # (which represents the final successful attempt)
                        results[cve_id] = success

            if results:
                unique_cves = len(results)
                logging.info(
                    f"Found existing results: {completed_count} total completed tests, {unique_cves} unique CVEs in {csv_filename}"
                )

                if completed_count > unique_cves:
                    logging.info(
                        f"Note: CSV contains {completed_count - unique_cves} duplicate entries (retries)"
                    )

            return results, completed_count
        except Exception as e:
            logging.warning(f"Could not read existing CSV file {csv_filename}: {e}")
            return {}, 0

    def cve_based_challenge_full_dataset(
        self,
        cve_dataset,
        debug=False,
        delay_between_queries=0.0,
        max_retries=1,
        delay_between_retries=30,
    ):
        csv_filename = f"{self.model_name.replace('/', '-')}.csv"

        # Load existing results to resume where we left off
        results, completed_count = self.load_existing_results(csv_filename)

        # Resume from the position where we left off (by count, not by CVE ID)
        # This handles datasets with duplicate CVE IDs correctly
        remaining_dataset = cve_dataset[completed_count:]

        if completed_count > 0:
            logging.info(
                f"Resuming from position {completed_count}. {len(remaining_dataset)} entries remaining out of {len(cve_dataset)} total"
            )
        else:
            logging.info(f"Starting fresh benchmark with {len(cve_dataset)} entries")

        if not remaining_dataset:
            logging.info("All dataset entries already completed!")
            return results

        with logging_redirect_tqdm():
            # Open in append mode if file exists, write mode if new
            file_mode = "a" if os.path.exists(csv_filename) else "w"
            with open(csv_filename, mode=file_mode, encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["cve_id", "success"])

                # Only write header if this is a new file
                if file_mode == "w":
                    writer.writeheader()

                for entry in tqdm.tqdm(
                    remaining_dataset, desc="Benchmark in progress..."
                ):
                    retries = 0
                    success = None

                    while retries <= max_retries and success is None:
                        try:
                            success = self.cve_based_challenge(entry, debug)
                        except Exception as err:
                            retries += 1
                            if retries <= max_retries:
                                logging.warning(
                                    f"Attempt {retries}/{max_retries + 1} failed for CVE {entry['cve_id']}: {err}"
                                )
                                if retries <= max_retries:
                                    logging.info(
                                        f"Retrying in {delay_between_retries} seconds..."
                                    )
                                    time.sleep(delay_between_retries)
                            else:
                                logging.error(
                                    f"All attempts failed for CVE {entry['cve_id']}: {err}"
                                )
                                raise err

                    results[entry["cve_id"]] = success
                    writer.writerow({"cve_id": entry["cve_id"], "success": success})
                    csvfile.flush()  # Ensure data is written immediately

                    if delay_between_queries:
                        time.sleep(delay_between_queries)

        return results


class ExperimentRunner:
    """Manages and runs multiple model experiments based on configuration."""

    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.results_dir = Path(self.config["global_settings"]["output_directory"])
        self.results_dir.mkdir(exist_ok=True)

    def load_config(self):
        """Load experiment configuration from JSON file."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            logging.info(f"Loaded configuration from {self.config_path}")
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file {self.config_path} not found!")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {e}")
            raise

    def run_single_experiment(self, experiment_config):
        """Run a single experiment based on its configuration."""
        experiment_name = experiment_config["name"]
        model_name = experiment_config["model"]

        logging.info(f"Starting experiment: {experiment_name} with model: {model_name}")

        rate_limit_config = experiment_config["rate_limit"]
        rate_limiter = RateLimiter(
            requests_per_minute=rate_limit_config["requests_per_minute"]
        )

        # Initialize model
        model = LLModel(model_name=model_name, rate_limiter=rate_limiter)

        # Load dataset
        dataset_config = experiment_config["dataset"]
        dataset = extract_data(dataset_config["path"])

        max_samples = dataset_config.get("max_samples")
        if max_samples and max_samples < len(dataset):
            dataset = dataset[:max_samples]
            logging.info(
                f"Limited dataset to {max_samples} samples for experiment {experiment_name}"
            )
            logging.info(f"Dataset size: {len(dataset)}")

        # Run benchmark
        retry_settings = experiment_config["retry_settings"]
        results = model.cve_based_challenge_full_dataset(
            dataset,
            debug=self.config["global_settings"]["debug_mode"],
            delay_between_queries=rate_limit_config["delay_between_queries"],
            max_retries=retry_settings["max_retries"],
            delay_between_retries=retry_settings["delay_between_retries"],
        )

        accuracy = sum(results.values()) / len(results) if results else 0

        self.save_experiment_results(experiment_name, model_name, results, accuracy)

        logging.info(
            f"Completed experiment: {experiment_name} - Accuracy: {accuracy:.4f}"
        )
        return {
            "experiment_name": experiment_name,
            "model_name": model_name,
            "accuracy": accuracy,
            "total_samples": len(results),
            "successful_samples": sum(results.values()),
        }

    def save_experiment_results(self, experiment_name, model_name, results, accuracy):
        """Save detailed experiment results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        summary = {
            "experiment_name": experiment_name,
            "model_name": model_name,
            "timestamp": timestamp,
            "accuracy": accuracy,
            "total_samples": len(results),
            "successful_samples": sum(results.values()),
            "detailed_results": results,
        }

        summary_path = self.results_dir / f"{experiment_name}_{timestamp}_summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        logging.info(f"Saved detailed results to {summary_path}")

    def run_all_experiments(self):
        """Run all enabled experiments from the configuration."""
        all_results = []
        enabled_experiments = [
            exp for exp in self.config["experiments"] if exp["enabled"]
        ]

        if not enabled_experiments:
            logging.warning("No experiments are enabled in the configuration!")
            return []

        logging.info(f"Running {len(enabled_experiments)} enabled experiments...")

        for experiment_config in enabled_experiments:
            try:
                result = self.run_single_experiment(experiment_config)
                all_results.append(result)
            except Exception as e:
                logging.error(f"Experiment {experiment_config['name']} failed: {e}")
                if self.config["global_settings"]["debug_mode"]:
                    raise
                continue

        self.save_overall_summary(all_results)

        return all_results

    def save_overall_summary(self, all_results):
        """Save a summary of all experiment results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        summary = {
            "timestamp": timestamp,
            "total_experiments": len(all_results),
            "experiments": all_results,
            "average_accuracy": sum(r["accuracy"] for r in all_results)
            / len(all_results)
            if all_results
            else 0,
        }

        summary_path = self.results_dir / f"overall_summary_{timestamp}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        logging.info(f"Saved overall summary to {summary_path}")

        # Print results table
        print("\n" + "=" * 80)
        print("EXPERIMENT RESULTS SUMMARY")
        print("=" * 80)
        print(f"{'Experiment Name':<30} {'Model':<30} {'Accuracy':<10} {'Samples':<8}")
        print("-" * 80)

        for result in all_results:
            print(
                f"{result['experiment_name']:<30} {result['model_name']:<30} "
                f"{result['accuracy']:<10.4f} {result['total_samples']:<8}"
            )

        if all_results:
            print("-" * 80)
            print(f"{'AVERAGE':<30} {'':<30} {summary['average_accuracy']:<10.4f}")
        print("=" * 80)


def main():
    """Main function to run experiments based on configuration."""
    runner = ExperimentRunner()
    results = runner.run_all_experiments()

    if not results:
        logging.error("No experiments completed successfully!")
        return

    logging.info("All experiments completed!")


if __name__ == "__main__":
    main()
