import yaml
import os
import re
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class CompareConfig:
    """Configuration for a single comparison source"""
    source: str
    map_file: str
    name: Optional[str] = None
    safe_name: Optional[str] = None
    rules: Optional[str] = None

    def __post_init__(self):
        if not self.name:
            # Extract filename without path or extension
            self.name = os.path.splitext(os.path.basename(self.source))[0]
        # Create a filesystem safe name
        self.safe_name = re.sub(r'[^a-zA-Z0-9]', '_', self.name).lower()

@dataclass
class Config:
    """Main configuration class that holds all configuration data"""
    truth_name: Optional[str]
    truth_source: str
    truth_map: str
    truth_rules: Optional[str]
    output_prefix: str
    rules: Optional[str]
    comparisons: List[CompareConfig]

    def __post_init__(self):
        if not self.truth_name:
            # Extract filename without path or extension
            self.truth_name = os.path.splitext(os.path.basename(self.truth_source))[0]

    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """
        Load configuration from a YAML file
        
        Args:
            config_path: Path to the YAML configuration file
            
        Returns:
            Config object with loaded configuration
            
        Raises:
            ValueError: If the configuration file is invalid or missing required fields
        """
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
        except (yaml.YAMLError, FileNotFoundError) as e:
            raise ValueError(f"Failed to load configuration file: {str(e)}")

        # Validate required fields
        if 'truth' not in config_data:
            raise ValueError("Missing required 'truth' section in configuration")
        
        truth = config_data['truth']
        if not isinstance(truth, dict):
            raise ValueError("'truth' section must be a dictionary")
            
        required_truth_fields = ['source', 'map']
        for field in required_truth_fields:
            if field not in truth:
                raise ValueError(f"Missing required field in truth section: {field}")

        # Parse comparisons if they exist
        comparisons = []
        if 'comparisons' in config_data:
            for comp in config_data['comparisons']:
                if not isinstance(comp, dict):
                    raise ValueError("Each comparison must be a dictionary")
                required_comp_fields = ['source', 'map']
                for field in required_comp_fields:
                    if field not in comp:
                        raise ValueError(f"Missing required field in comparison: {field}")
                comparisons.append(CompareConfig(
                    name=comp.get('name'),
                    source=comp['source'],
                    map_file=comp['map'],
                    rules=comp.get('rules')
                ))

        return cls(
            truth_name=truth.get('name'),
            truth_source=truth['source'],
            truth_map=truth['map'],
            truth_rules=truth.get('rules'),
            output_prefix=config_data.get('output', 'output'),
            rules=config_data.get('rules'),
            comparisons=comparisons
        )