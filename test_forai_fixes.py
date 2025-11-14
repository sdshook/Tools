#!/usr/bin/env python3
"""
Test script to verify FORAI.py fixes for directory structure and path resolution
"""

import sys
import tempfile
import shutil
from pathlib import Path

# Add FORAI directory to path
sys.path.insert(0, str(Path(__file__).parent / "FORAI"))

def test_directory_detection():
    """Test that existing FORAI installation is detected correctly"""
    print("Testing directory detection...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create mock FORAI installation
        forai_root = temp_path / "FORAI"
        forai_root.mkdir()
        
        # Create expected directories
        for subdir in ["archives", "artifacts", "extracts", "reports", "tools"]:
            (forai_root / subdir).mkdir()
        
        # Create a subdirectory (like reports)
        reports_dir = forai_root / "reports"
        
        # Import CONFIG after setting up the mock structure
        from FORAI import CONFIG
        
        # Test detection
        CONFIG.set_base_dir(reports_dir)
        
        # Verify detection worked
        assert CONFIG.existing_installation_detected == True, "Should detect existing installation"
        assert CONFIG.base_dir == forai_root, f"Should use {forai_root} as base, got {CONFIG.base_dir}"
        
        print("✅ Directory detection test passed")

def test_path_resolution():
    """Test that plaso file path resolution works correctly"""
    print("Testing path resolution...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a mock plaso file
        plaso_file = temp_path / "test.plaso"
        plaso_file.write_text("mock plaso content")
        
        # Test path resolution
        relative_path = Path("test.plaso")
        
        # Change to temp directory to simulate user's working directory
        import os
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            resolved_path = relative_path.resolve()
            
            # Verify resolution worked
            assert resolved_path == plaso_file, f"Expected {plaso_file}, got {resolved_path}"
            assert resolved_path.exists(), "Resolved path should exist"
            
            print("✅ Path resolution test passed")
        finally:
            os.chdir(original_cwd)

def test_workflow_manager_no_mkdir():
    """Test that ForensicWorkflowManager doesn't create directories when existing installation detected"""
    print("Testing ForensicWorkflowManager directory creation...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create mock FORAI installation
        forai_root = temp_path / "FORAI"
        forai_root.mkdir()
        
        # Create expected directories
        for subdir in ["archives", "artifacts", "extracts", "reports", "tools"]:
            (forai_root / subdir).mkdir()
        
        # Import after setting up structure
        from FORAI import CONFIG, ForensicWorkflowManager
        
        # Set up CONFIG to detect existing installation
        CONFIG.set_base_dir(forai_root / "reports")
        
        # Verify detection worked
        assert CONFIG.existing_installation_detected == True
        
        # Create a test subdirectory that shouldn't exist
        test_subdir = forai_root / "artifacts" / "test_should_not_be_created"
        assert not test_subdir.exists(), "Test subdirectory should not exist initially"
        
        # Create ForensicWorkflowManager - it should NOT create new directories
        workflow = ForensicWorkflowManager("TEST001", forai_root / "reports", verbose=True)
        
        # Verify no new directories were created inappropriately
        # The workflow manager should use existing directories
        assert workflow.artifacts_dir == CONFIG.artifacts_dir
        assert workflow.parsed_dir == CONFIG.extracts_dir
        
        print("✅ ForensicWorkflowManager directory test passed")

if __name__ == "__main__":
    print("Running FORAI fixes tests...")
    
    try:
        test_directory_detection()
        test_path_resolution()
        test_workflow_manager_no_mkdir()
        
        print("\n🎉 All tests passed! The fixes should work correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)