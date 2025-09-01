#!/usr/bin/env python3
"""
Analysis and visualization script for Code Vulnerability LLM Benchmark results.

This script analyzes CSV result files to provide comprehensive insights into model performance,
including per-CVE analysis, model comparisons, and various visualizations.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import argparse
import os
import glob
from pathlib import Path
from typing import Dict, List, Tuple
import logging
from collections import Counter, defaultdict
import json
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set style for better plots
plt.style.use('default')
sns.set_palette("husl")


class ResultsAnalyzer:
    def __init__(self, results_dir: str = "."):
        """
        Initialize the analyzer with results directory.
        
        Args:
            results_dir: Directory containing CSV result files
        """
        self.results_dir = Path(results_dir)
        self.results_data = {}
        self.combined_df = None
        self.output_dir = Path("analysis_output")
        self.output_dir.mkdir(exist_ok=True)
        
    def load_all_results(self):
        """Load all CSV result files from the directory."""
        logger.info(f"Loading results from {self.results_dir}")
        
        # Find all CSV files that look like model results
        csv_files = list(self.results_dir.glob("*.csv"))
        csv_files = [f for f in csv_files if not f.name.startswith('analysis_')]  # Exclude our output files
        
        if not csv_files:
            logger.error("No CSV result files found!")
            return
            
        logger.info(f"Found {len(csv_files)} CSV files")
        
        all_data = []
        
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file)
                
                # Extract model name from filename
                model_name = csv_file.stem.replace("openrouter-","")
                df['model'] = model_name
                df['file_name'] = csv_file.name
                
                # Add row index to match with original dataset order
                df['dataset_index'] = df.index
                
                # Convert success to boolean if it's string
                if df['success'].dtype == 'object':
                    df['success'] = df['success'].astype(str).str.lower().map({'true': True, 'false': False})
                
                self.results_data[model_name] = df
                all_data.append(df)
                
                logger.info(f"Loaded {len(df)} results from {csv_file.name}")
                
            except Exception as e:
                logger.error(f"Error loading {csv_file}: {e}")
                continue
        
        if all_data:
            self.combined_df = pd.concat(all_data, ignore_index=True)
            logger.info(f"Combined dataset contains {len(self.combined_df)} total results")
        else:
            logger.error("No data could be loaded!")
    
    def generate_summary_statistics(self):
        """Generate comprehensive summary statistics."""
        logger.info("Generating summary statistics...")
        
        if self.combined_df is None:
            logger.error("No data loaded!")
            return
        
        summary_stats = {}
        
        # Overall statistics
        for model_name, df in self.results_data.items():
            total_tests = len(df)
            successful_tests = df['success'].sum()
            accuracy = successful_tests / total_tests if total_tests > 0 else 0
            
            # CVE-level analysis
            cve_stats = df.groupby('cve_id')['success'].agg(['count', 'sum', 'mean']).reset_index()
            cve_stats.columns = ['cve_id', 'total_tests', 'successful_tests', 'accuracy']
            
            # Count unique CVEs
            unique_cves = len(df['cve_id'].unique())
            
            # CVE duplicate analysis
            cve_counts = df['cve_id'].value_counts()
            max_duplicates = cve_counts.max()
            avg_duplicates = cve_counts.mean()
            
            summary_stats[model_name] = {
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'failed_tests': total_tests - successful_tests,
                'overall_accuracy': accuracy,
                'unique_cves': unique_cves,
                'max_duplicates_per_cve': max_duplicates,
                'avg_tests_per_cve': avg_duplicates,
                'cve_level_stats': cve_stats
            }
        
        # Save summary statistics
        summary_file = self.output_dir / "summary_statistics.json"
        with open(summary_file, 'w') as f:
            # Convert numpy types to native Python types for JSON serialization
            json_stats = {}
            for model, stats in summary_stats.items():
                json_stats[model] = {
                    k: v for k, v in stats.items() 
                    if k != 'cve_level_stats'  # Skip DataFrame for JSON
                }
                # Convert numpy types
                for key, value in json_stats[model].items():
                    if hasattr(value, 'item'):  # numpy scalar
                        json_stats[model][key] = value.item()
            
            json.dump(json_stats, f, indent=2)
        
        logger.info(f"Summary statistics saved to {summary_file}")
        return summary_stats
    
    def create_accuracy_comparison_plot(self):
        """Create a bar plot comparing accuracy across models."""
        logger.info("Creating accuracy comparison plot...")
        
        if not self.results_data:
            return
        
        models = []
        accuracies = []
        total_tests = []
        
        for model_name, df in self.results_data.items():
            accuracy = df['success'].mean()
            models.append(model_name.replace('-', '\n'))  # Break long names
            accuracies.append(accuracy)
            total_tests.append(len(df))
        
        # Create the plot
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Accuracy plot
        bars1 = ax1.bar(models, accuracies, color=sns.color_palette("husl", len(models)))
        ax1.set_title('Model Accuracy Comparison', fontsize=16, fontweight='bold')
        ax1.set_ylabel('Accuracy', fontsize=12)
        ax1.set_ylim(0, 1)
        
        # Add accuracy labels on bars
        for bar, acc in zip(bars1, accuracies):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{acc:.3f}', ha='center', va='bottom', fontweight='bold')
        
        # Total tests plot
        bars2 = ax2.bar(models, total_tests, color=sns.color_palette("husl", len(models)))
        ax2.set_title('Number of Tests per Model', fontsize=16, fontweight='bold')
        ax2.set_ylabel('Number of Tests', fontsize=12)
        ax2.set_xlabel('Models', fontsize=12)
        
        # Add count labels on bars
        for bar, count in zip(bars2, total_tests):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + max(total_tests)*0.01,
                    f'{count}', ha='center', va='bottom', fontweight='bold')
        
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        plot_file = self.output_dir / "accuracy_comparison.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Accuracy comparison plot saved to {plot_file}")
    
    def create_per_cve_analysis(self):
        """Analyze performance per CVE and create visualizations."""
        logger.info("Creating per-CVE analysis...")
        
        if self.combined_df is None:
            return
        
        # Group by CVE and calculate statistics
        cve_analysis = self.combined_df.groupby(['cve_id', 'model'])['success'].agg(['count', 'sum', 'mean']).reset_index()
        cve_analysis.columns = ['cve_id', 'model', 'total_tests', 'successful_tests', 'accuracy']
        
        # Find CVEs that appear across multiple models
        cve_model_counts = self.combined_df.groupby('cve_id')['model'].nunique().reset_index()
        cve_model_counts.columns = ['cve_id', 'num_models']
        
        # CVEs tested by multiple models
        multi_model_cves = cve_model_counts[cve_model_counts['num_models'] > 1]['cve_id'].tolist()
        
        if multi_model_cves:
            # Create comparison plot for CVEs tested by multiple models
            fig, ax = plt.subplots(figsize=(15, 8))
            
            # Pivot for easier plotting
            pivot_data = cve_analysis[cve_analysis['cve_id'].isin(multi_model_cves[:20])]  # Limit to first 20
            pivot_df = pivot_data.pivot(index='cve_id', columns='model', values='accuracy')
            
            # Create heatmap
            sns.heatmap(pivot_df, annot=True, cmap='RdYlGn', center=0.5, 
                       cbar_kws={'label': 'Accuracy'}, fmt='.2f')
            plt.title('Per-CVE Accuracy Heatmap (Multi-Model CVEs)', fontsize=16, fontweight='bold')
            plt.xlabel('Models', fontsize=12)
            plt.ylabel('CVE IDs', fontsize=12)
            plt.xticks(rotation=45, ha='right')
            plt.yticks(rotation=0)
            plt.tight_layout()
            
            plot_file = self.output_dir / "per_cve_heatmap.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Per-CVE heatmap saved to {plot_file}")
        
        # Save detailed CVE analysis
        cve_analysis_file = self.output_dir / "per_cve_analysis.csv"
        cve_analysis.to_csv(cve_analysis_file, index=False)
        logger.info(f"Detailed CVE analysis saved to {cve_analysis_file}")
        
        return cve_analysis
    
    def create_distribution_plots(self):
        """Create distribution plots for various metrics."""
        logger.info("Creating distribution plots...")
        
        if not self.results_data:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. Success rate distribution across models
        success_rates = [df['success'].mean() for df in self.results_data.values()]
        model_names = list(self.results_data.keys())
        
        axes[0, 0].hist(success_rates, bins=10, alpha=0.7, color='skyblue', edgecolor='black')
        axes[0, 0].set_title('Distribution of Model Accuracies', fontweight='bold')
        axes[0, 0].set_xlabel('Accuracy')
        axes[0, 0].set_ylabel('Count')
        
        # 2. CVE duplicate count distribution
        all_cve_counts = []
        for df in self.results_data.values():
            cve_counts = df['cve_id'].value_counts()
            all_cve_counts.extend(cve_counts.tolist())
        
        axes[0, 1].hist(all_cve_counts, bins=20, alpha=0.7, color='lightcoral', edgecolor='black')
        axes[0, 1].set_title('Distribution of Tests per CVE', fontweight='bold')
        axes[0, 1].set_xlabel('Number of Tests per CVE')
        axes[0, 1].set_ylabel('Count')
        
        # 3. Success rate by model (violin plot)
        if len(self.results_data) > 1:
            success_data = []
            model_labels = []
            for model, df in self.results_data.items():
                # Get per-CVE success rates for this model
                cve_success_rates = df.groupby('cve_id')['success'].mean()
                success_data.extend(cve_success_rates.tolist())
                model_labels.extend([model] * len(cve_success_rates))
            
            success_df = pd.DataFrame({'Model': model_labels, 'CVE_Accuracy': success_data})
            sns.violinplot(data=success_df, x='Model', y='CVE_Accuracy', ax=axes[1, 0])
            axes[1, 0].set_title('Per-CVE Accuracy Distribution by Model', fontweight='bold')
            axes[1, 0].tick_params(axis='x', rotation=45)
        else:
            axes[1, 0].text(0.5, 0.5, 'Need multiple models\nfor comparison', 
                           ha='center', va='center', transform=axes[1, 0].transAxes)
            axes[1, 0].set_title('Per-CVE Accuracy Distribution by Model', fontweight='bold')
        
        # 4. Overall success vs failure counts
        total_success = sum(df['success'].sum() for df in self.results_data.values())
        total_failure = sum((~df['success']).sum() for df in self.results_data.values())
        
        axes[1, 1].pie([total_success, total_failure], labels=['Success', 'Failure'], 
                      autopct='%1.1f%%', startangle=90, colors=['lightgreen', 'lightcoral'])
        axes[1, 1].set_title('Overall Success vs Failure Distribution', fontweight='bold')
        
        plt.tight_layout()
        
        plot_file = self.output_dir / "distribution_plots.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Distribution plots saved to {plot_file}")
    
    def create_detailed_comparison_table(self):
        """Create a detailed comparison table of all models."""
        logger.info("Creating detailed comparison table...")
        
        if not self.results_data:
            return
        
        comparison_data = []
        
        for model_name, df in self.results_data.items():
            total_tests = len(df)
            successful_tests = df['success'].sum()
            failed_tests = total_tests - successful_tests
            accuracy = successful_tests / total_tests if total_tests > 0 else 0
            
            # CVE-level statistics
            unique_cves = len(df['cve_id'].unique())
            cve_success_rates = df.groupby('cve_id')['success'].mean()
            
            comparison_data.append({
                'Model': model_name,
                'Total Tests': total_tests,
                'Successful Tests': successful_tests,
                'Failed Tests': failed_tests,
                'Overall Accuracy': f"{accuracy:.3f}",
                'Unique CVEs': unique_cves,
                'Avg Tests per CVE': f"{total_tests / unique_cves:.1f}",
                'Best CVE Accuracy': f"{cve_success_rates.max():.3f}",
                'Worst CVE Accuracy': f"{cve_success_rates.min():.3f}",
                'Std Dev CVE Accuracy': f"{cve_success_rates.std():.3f}"
            })
        
        comparison_df = pd.DataFrame(comparison_data)
        
        # Sort by accuracy
        comparison_df['accuracy_sort'] = comparison_df['Overall Accuracy'].astype(float)
        comparison_df = comparison_df.sort_values('accuracy_sort', ascending=False)
        comparison_df = comparison_df.drop('accuracy_sort', axis=1)
        
        # Save to CSV
        table_file = self.output_dir / "model_comparison_table.csv"
        comparison_df.to_csv(table_file, index=False)
        
        # Create a nice formatted table plot
        fig, ax = plt.subplots(figsize=(16, len(comparison_df) * 0.8 + 2))
        ax.axis('tight')
        ax.axis('off')
        
        table = ax.table(cellText=comparison_df.values,
                        colLabels=comparison_df.columns,
                        cellLoc='center',
                        loc='center')
        
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1.2, 1.5)
        
        # Color code by accuracy
        for i in range(len(comparison_df)):
            accuracy = float(comparison_df.iloc[i]['Overall Accuracy'])
            if accuracy >= 0.8:
                color = 'lightgreen'
            elif accuracy >= 0.6:
                color = 'lightyellow'
            else:
                color = 'lightcoral'
            
            for j in range(len(comparison_df.columns)):
                table[(i + 1, j)].set_facecolor(color)
        
        plt.title('Model Performance Comparison Table', fontsize=16, fontweight='bold', pad=20)
        
        table_plot_file = self.output_dir / "model_comparison_table.png"
        plt.savefig(table_plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Comparison table saved to {table_file} and {table_plot_file}")
        return comparison_df
    
    def generate_full_report(self):
        """Generate a comprehensive analysis report."""
        logger.info("Generating full analysis report...")
        
        if not self.results_data:
            logger.error("No data loaded for analysis!")
            return
        
        # Generate all analyses
        summary_stats = self.generate_summary_statistics()
        self.create_accuracy_comparison_plot()
        cve_analysis = self.create_per_cve_analysis()
        self.create_distribution_plots()
        comparison_table = self.create_detailed_comparison_table()
        
        # Create summary report
        report_lines = []
        report_lines.append("# Code Vulnerability LLM Benchmark - Analysis Report")
        report_lines.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        report_lines.append("## Summary Statistics")
        for model_name, stats in summary_stats.items():
            report_lines.append(f"### {model_name}")
            report_lines.append(f"- Total Tests: {stats['total_tests']}")
            report_lines.append(f"- Successful Tests: {stats['successful_tests']}")
            report_lines.append(f"- Overall Accuracy: {stats['overall_accuracy']:.3f}")
            report_lines.append(f"- Unique CVEs: {stats['unique_cves']}")
            report_lines.append(f"- Average Tests per CVE: {stats['avg_tests_per_cve']:.1f}")
            report_lines.append("")
        
        report_lines.append("## Files Generated")
        report_lines.append("- `accuracy_comparison.png`: Model accuracy comparison")
        report_lines.append("- `per_cve_heatmap.png`: Per-CVE accuracy heatmap")
        report_lines.append("- `distribution_plots.png`: Various distribution analyses")
        report_lines.append("- `model_comparison_table.csv/png`: Detailed comparison table")
        report_lines.append("- `per_cve_analysis.csv`: Detailed per-CVE analysis")
        report_lines.append("- `summary_statistics.json`: Raw statistics in JSON format")
        
        # Save report
        report_file = self.output_dir / "analysis_report.md"
        with open(report_file, 'w') as f:
            f.write('\n'.join(report_lines))
        
        logger.info(f"Full analysis report saved to {report_file}")
        logger.info(f"All analysis files saved to {self.output_dir}")
        
        return summary_stats

    def analyze_failure_patterns(self, results: Dict[str, pd.DataFrame]) -> None:
        """Analyze patterns in failures across models and CVEs."""
        logger.info("Analyzing failure patterns...")
        
        # Combine all results to find common failure patterns
        all_failures = []
        for model_name, df in results.items():
            failures = df[df['success'] == False].copy()
            failures['model'] = model_name
            all_failures.append(failures)
        
        if not all_failures:
            return
            
        combined_failures = pd.concat(all_failures, ignore_index=True)
        
        # Analyze CVEs that are consistently difficult
        cve_failure_rates = combined_failures.groupby('cve_id').size().sort_values(ascending=False)
        
        # Create failure pattern visualization
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 16))
        
        # Top 20 most failed CVEs
        top_failed_cves = cve_failure_rates.head(20)
        ax1.barh(range(len(top_failed_cves)), top_failed_cves.values)
        ax1.set_yticks(range(len(top_failed_cves)))
        ax1.set_yticklabels([f"{cve[:15]}..." if len(cve) > 15 else cve for cve in top_failed_cves.index])
        ax1.set_xlabel('Number of Model Failures')
        ax1.set_title('Top 20 Most Failed CVEs Across All Models')
        ax1.grid(True, alpha=0.3)
        
        # Model failure distribution
        model_failures = combined_failures['model'].value_counts()
        ax2.bar(range(len(model_failures)), model_failures.values)
        ax2.set_xticks(range(len(model_failures)))
        ax2.set_xticklabels([name.split('-')[-1] for name in model_failures.index], rotation=45, ha='right')
        ax2.set_ylabel('Number of Failures')
        ax2.set_title('Total Failures by Model')
        ax2.grid(True, alpha=0.3)
        
        # Failure rate by number of tests per CVE
        for model_name, df in results.items():
            cve_test_counts = df.groupby('cve_id').size()
            cve_failure_rates = 1 - df.groupby('cve_id')['success'].mean()
            ax3.scatter(cve_test_counts, cve_failure_rates, alpha=0.6, label=model_name.split('-')[-1])
        
        ax3.set_xlabel('Number of Tests per CVE')
        ax3.set_ylabel('Failure Rate')
        ax3.set_title('Failure Rate vs Tests per CVE')
        ax3.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        ax3.grid(True, alpha=0.3)
        
        # Overall failure rate distribution
        all_failure_rates = []
        for model_name, df in results.items():
            model_failure_rate = 1 - df['success'].mean()
            all_failure_rates.append(model_failure_rate)
        
        ax4.hist(all_failure_rates, bins=10, alpha=0.7, edgecolor='black')
        ax4.set_xlabel('Failure Rate')
        ax4.set_ylabel('Number of Models')
        ax4.set_title('Distribution of Model Failure Rates')
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / "failure_patterns.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # Save detailed failure analysis
        failure_analysis = {
            'most_failed_cves': top_failed_cves.to_dict(),
            'model_failure_counts': model_failures.to_dict(),
            'overall_failure_rates': {
                'mean': np.mean(all_failure_rates),
                'std': np.std(all_failure_rates),
                'min': np.min(all_failure_rates),
                'max': np.max(all_failure_rates)
            }
        }
        
        with open(self.output_dir / "failure_analysis.json", 'w') as f:
            json.dump(failure_analysis, f, indent=2)

    def analyze_model_consistency(self, results: Dict[str, pd.DataFrame]) -> None:
        """Analyze consistency of model performance across different CVEs."""
        logger.info("Analyzing model consistency...")
        
        # Calculate per-CVE accuracy for each model
        model_cve_performance = {}
        all_cves = set()
        
        for model_name, df in results.items():
            cve_accuracy = df.groupby('cve_id')['success'].mean()
            model_cve_performance[model_name] = cve_accuracy
            all_cves.update(cve_accuracy.index)
        
        # Create consistency analysis
        consistency_data = []
        for model_name, cve_accuracy in model_cve_performance.items():
            consistency_data.append({
                'Model': model_name,
                'Mean Accuracy': cve_accuracy.mean(),
                'Std Dev Accuracy': cve_accuracy.std(),
                'Min Accuracy': cve_accuracy.min(),
                'Max Accuracy': cve_accuracy.max(),
                'Coefficient of Variation': cve_accuracy.std() / cve_accuracy.mean() if cve_accuracy.mean() > 0 else 0,
                'CVEs Tested': len(cve_accuracy)
            })
        
        consistency_df = pd.DataFrame(consistency_data)
        consistency_df = consistency_df.sort_values('Coefficient of Variation')
        
        # Save consistency analysis
        consistency_df.to_csv(self.output_dir / "model_consistency.csv", index=False)
        
        # Create consistency visualization
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 8))
        
        # Coefficient of variation comparison
        models = [name.split('-')[-1] for name in consistency_df['Model']]
        ax1.barh(range(len(models)), consistency_df['Coefficient of Variation'])
        ax1.set_yticks(range(len(models)))
        ax1.set_yticklabels(models)
        ax1.set_xlabel('Coefficient of Variation (Lower = More Consistent)')
        ax1.set_title('Model Consistency Comparison')
        ax1.grid(True, alpha=0.3)
        
        # Accuracy vs consistency scatter plot
        ax2.scatter(consistency_df['Mean Accuracy'], consistency_df['Coefficient of Variation'])
        for i, model in enumerate(models):
            ax2.annotate(model, 
                        (consistency_df.iloc[i]['Mean Accuracy'], 
                         consistency_df.iloc[i]['Coefficient of Variation']),
                        xytext=(5, 5), textcoords='offset points', fontsize=8)
        
        ax2.set_xlabel('Mean Accuracy')
        ax2.set_ylabel('Coefficient of Variation')
        ax2.set_title('Accuracy vs Consistency Trade-off')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / "model_consistency.png", dpi=300, bbox_inches='tight')
        plt.close()


def main():
    """Main function to run the analysis."""
    parser = argparse.ArgumentParser(description="Analyze Code Vulnerability LLM Benchmark results")
    parser.add_argument("--results-dir", "-d", default=".", 
                       help="Directory containing CSV result files (default: current directory)")
    parser.add_argument("--output-dir", "-o", default="analysis_output",
                       help="Output directory for analysis results (default: analysis_output)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize analyzer
    analyzer = ResultsAnalyzer(args.results_dir)
    if args.output_dir != "analysis_output":
        analyzer.output_dir = Path(args.output_dir)
        analyzer.output_dir.mkdir(exist_ok=True)
    
    # Load data and generate analysis
    analyzer.load_all_results()
    
    if not analyzer.results_data:
        logger.error("No results data loaded. Exiting.")
        return
    
    # Generate full analysis
    summary_stats = analyzer.generate_full_report()
    
    # Print summary to console
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE - SUMMARY")
    print("="*80)
    
    for model_name, stats in summary_stats.items():
        print(f"{model_name}:")
        print(f"  Accuracy: {stats['overall_accuracy']:.3f} ({stats['successful_tests']}/{stats['total_tests']})")
        print(f"  Unique CVEs: {stats['unique_cves']}")
    
    print(f"\nAll analysis files saved to: {analyzer.output_dir}")
    print("="*80)


if __name__ == "__main__":
    main()
