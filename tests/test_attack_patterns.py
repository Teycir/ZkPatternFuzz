#!/usr/bin/env python3
"""
Test script to validate attack_patterns.yaml structure
"""
import yaml
import sys
from pathlib import Path


def load_yaml_with_duplicate_check(file_path):
    """Load YAML and detect duplicate keys"""
    class DuplicateKeyLoader(yaml.SafeLoader):
        pass
    
    def constructor(loader, node):
        mapping = {}
        duplicates = []
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in mapping:
                duplicates.append(key)
            mapping[key] = loader.construct_object(value_node)
        
        if duplicates:
            raise yaml.constructor.ConstructorError(
                f"Found duplicate keys: {duplicates}",
                node.start_mark
            )
        return mapping
    
    DuplicateKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        constructor
    )
    
    with open(file_path, 'r') as f:
        return yaml.load(f, Loader=DuplicateKeyLoader)


def validate_patterns(data):
    """Validate patterns section"""
    errors = []
    warnings = []
    
    if 'patterns' not in data:
        errors.append("Missing 'patterns' section")
        return errors, warnings
    
    patterns = data['patterns']
    expected_patterns = [
        'merkle_tree', 'nullifier', 'range_proof', 'signature', 
        'hash_function', 'encryption', 'front_running', 'mev_extraction',
        'griefing', 'batch_verification', 'zkevm', 'recursive_snark',
        'proof_aggregation'
    ]
    
    for pattern_name in expected_patterns:
        if pattern_name not in patterns:
            warnings.append(f"Pattern '{pattern_name}' not found")
        else:
            pattern = patterns[pattern_name]
            if 'description' not in pattern:
                warnings.append(f"Pattern '{pattern_name}' missing description")
            if 'attacks' not in pattern:
                errors.append(f"Pattern '{pattern_name}' missing attacks list")
            else:
                for i, attack in enumerate(pattern['attacks']):
                    if 'type' not in attack:
                        errors.append(f"Attack {i} in '{pattern_name}' missing type")
                    if 'description' not in attack:
                        warnings.append(f"Attack {i} in '{pattern_name}' missing description")
    
    return errors, warnings


def validate_interesting_values(data):
    """Validate interesting_values section"""
    errors = []
    warnings = []
    
    if 'interesting_values' not in data:
        warnings.append("Missing 'interesting_values' section")
        return errors, warnings
    
    values = data['interesting_values']
    expected_categories = [
        'bn254_scalar', 'bn254_base', 'common', 'zkevm_evm',
        'gas_values', 'storage_slots'
    ]
    
    for category in expected_categories:
        if category not in values:
            warnings.append(f"interesting_values missing category '{category}'")
        elif not isinstance(values[category], list):
            errors.append(f"interesting_values['{category}'] should be a list")
    
    return errors, warnings


def validate_mutation_strategies(data):
    """Validate mutation_strategies section"""
    errors = []
    warnings = []
    
    if 'mutation_strategies' not in data:
        warnings.append("Missing 'mutation_strategies' section")
        return errors, warnings
    
    strategies = data['mutation_strategies']
    expected_strategies = ['conservative', 'aggressive', 'boundary_focused']
    
    for strategy_name in expected_strategies:
        if strategy_name not in strategies:
            warnings.append(f"mutation_strategies missing '{strategy_name}'")
        else:
            strategy = strategies[strategy_name]
            if 'description' not in strategy:
                warnings.append(f"Strategy '{strategy_name}' missing description")
            if 'mutations' not in strategy:
                errors.append(f"Strategy '{strategy_name}' missing mutations list")
            else:
                for i, mutation in enumerate(strategy['mutations']):
                    if 'name' not in mutation:
                        errors.append(f"Mutation {i} in '{strategy_name}' missing name")
                    if 'probability' not in mutation:
                        errors.append(f"Mutation {i} in '{strategy_name}' missing probability")
    
    return errors, warnings


def validate_no_misplaced_attacks(data):
    """Check that attack patterns are not under wrong sections"""
    errors = []
    
    # Check mutation_strategies doesn't have attacks
    if 'mutation_strategies' in data:
        for strategy_name, strategy in data['mutation_strategies'].items():
            if 'attacks' in strategy:
                errors.append(f"mutation_strategies['{strategy_name}'] incorrectly contains 'attacks' - should only have 'mutations'")
    
    # Check interesting_values doesn't have attacks
    if 'interesting_values' in data:
        for category_name, category in data['interesting_values'].items():
            if isinstance(category, dict) and 'attacks' in category:
                errors.append(f"interesting_values['{category_name}'] incorrectly contains 'attacks'")
    
    return errors


def main():
    # Get the path to attack_patterns.yaml
    repo_root = Path(__file__).parent.parent
    yaml_file = repo_root / "templates" / "attack_patterns.yaml"
    
    if not yaml_file.exists():
        print(f"❌ ERROR: {yaml_file} not found")
        return 1
    
    print(f"🔍 Validating {yaml_file}\n")
    
    # Load and check for duplicates
    try:
        data = load_yaml_with_duplicate_check(yaml_file)
        print("✅ No duplicate keys found")
    except yaml.constructor.ConstructorError as e:
        print(f"❌ ERROR: {e}")
        return 1
    except Exception as e:
        print(f"❌ ERROR loading YAML: {e}")
        return 1
    
    # Validate structure
    all_errors = []
    all_warnings = []
    
    errors, warnings = validate_patterns(data)
    all_errors.extend(errors)
    all_warnings.extend(warnings)
    
    errors, warnings = validate_interesting_values(data)
    all_errors.extend(errors)
    all_warnings.extend(warnings)
    
    errors, warnings = validate_mutation_strategies(data)
    all_errors.extend(errors)
    all_warnings.extend(warnings)
    
    all_errors.extend(validate_no_misplaced_attacks(data))
    
    # Report results
    print(f"✅ YAML is well-formed")
    print(f"✅ Structure validation passed")
    
    if all_warnings:
        print(f"\n⚠️  {len(all_warnings)} Warning(s):")
        for warning in all_warnings:
            print(f"  - {warning}")
    
    if all_errors:
        print(f"\n❌ {len(all_errors)} Error(s):")
        for error in all_errors:
            print(f"  - {error}")
        return 1
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"  - {len(data.get('patterns', {}))} attack patterns")
    print(f"  - {len(data.get('interesting_values', {}))} interesting value categories")
    print(f"  - {len(data.get('mutation_strategies', {}))} mutation strategies")
    
    print("\n✅ All validations passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
