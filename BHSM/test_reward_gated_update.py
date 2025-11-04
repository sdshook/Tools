#!/usr/bin/env python3
"""
Test reward-gated update with EQ/IQ integration
"""

import time
import numpy as np
from BHSM import BDHMemory
from eq_iq_regulator import ContextEvent, FeedbackEvent

def test_reward_gated_update():
    """Test reward-gated update with EQ/IQ modulation"""
    print("Testing reward-gated update with EQ/IQ...")
    
    memory = BDHMemory()
    
    # Add a memory trace (use 32-dimensional vector to match EMBED_DIM)
    trace_id = "test_trace_001"
    vector = np.random.random(32) * 0.5 + 0.25  # Random vector in [0.25, 0.75]
    memory.add_or_update(trace_id, vector, 0.5)
    print(f"Added trace: {trace_id}")
    
    # Check the stored vector shape
    entry = memory.storage[trace_id]
    print(f"Stored vector shape: {entry['vec'].shape}")
    print(f"Eligibility pos shape: {entry['elig_pos'].shape}")
    print(f"Eligibility neg shape: {entry['elig_neg'].shape}")
    
    # Create context and feedback events
    context = ContextEvent(
        timestamp=time.time(),
        context_stability=0.8,
        threat_level=0.3,
        response_appropriateness=0.9
    )
    
    feedback = FeedbackEvent(
        timestamp=time.time(),
        predicted_threat=0.7,
        actual_threat=0.6,
        accuracy=0.9
    )
    
    print(f"Context: stability={context.context_stability}, threat={context.threat_level}")
    print(f"Feedback: predicted={feedback.predicted_threat}, actual={feedback.actual_threat}")
    
    # Apply reward-gated update - use same shape as stored vector
    state_vec = entry['vec'] + np.random.random(entry['vec'].shape) * 0.1
    print(f"State vector shape: {state_vec.shape}")
    
    try:
        memory.reward_gated_update(
            trace_id, 
            state_vec, 
            0.8,  # reward
            context.context_stability,
            context.threat_level,
            context.response_appropriateness,
            feedback.predicted_threat,
            feedback.actual_threat
        )
        print("Reward-gated update successful!")
        
        # Check the results
        entry = memory.storage[trace_id]
        print(f"Cumulative reward: {entry['cumulative_reward']}")
        print(f"EQ/IQ history length: {len(entry['eq_iq_history'])}")
        
        if entry['eq_iq_history']:
            latest = entry['eq_iq_history'][-1]
            print(f"Latest EQ/IQ: EQ={latest['eq']:.3f}, IQ={latest['iq']:.3f}, balance={latest['balance']:.3f}")
        
        return True
        
    except Exception as e:
        print(f"Error in reward-gated update: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    test_reward_gated_update()