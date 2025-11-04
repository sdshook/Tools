#!/usr/bin/env python3
"""
Basic test for BHSM EQ/IQ integration
"""

import time
from BHSM import BDHMemory
from eq_iq_regulator import ExperientialBehavioralRegulator, ContextEvent, FeedbackEvent

def test_basic_functionality():
    """Test basic EQ/IQ functionality"""
    print("Testing BHSM EQ/IQ integration...")
    
    # Test regulator initialization
    regulator = ExperientialBehavioralRegulator(alpha=0.6, beta=0.4, learning_rate=0.01)
    stats = regulator.get_stats()
    print(f"Regulator stats: {stats}")
    
    # Test BDH memory has regulator
    memory = BDHMemory()
    eq_iq_stats = memory.get_eq_iq_stats()
    print(f"Memory EQ/IQ stats: {eq_iq_stats}")
    
    # Test creating events
    context = ContextEvent(
        timestamp=time.time(),
        context_stability=0.8,
        threat_level=0.3,
        response_appropriateness=0.9
    )
    print(f"Context event: stability={context.context_stability}, threat={context.threat_level}, appropriateness={context.response_appropriateness}")
    
    feedback = FeedbackEvent(
        timestamp=time.time(),
        predicted_threat=0.7,
        actual_threat=0.6,
        accuracy=0.9
    )
    print(f"Feedback event: predicted={feedback.predicted_threat}, actual={feedback.actual_threat}, accuracy={feedback.accuracy}")
    
    # Test EQ/IQ balance calculation
    try:
        balance = regulator.calculate_eq_iq_balance(context, feedback)
        print(f"EQ/IQ balance: EQ={balance.eq:.3f}, IQ={balance.iq:.3f}, balance={balance.balance:.3f}")
    except Exception as e:
        print(f"Error calculating EQ/IQ balance: {e}")
        return False
    
    print("Basic functionality test passed!")
    return True

if __name__ == '__main__':
    test_basic_functionality()