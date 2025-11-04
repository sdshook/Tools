"""
EQ/IQ Balanced Reward System for RHLS
Implements experiential behavioral regulator with empathy (EQ) and accuracy (IQ) balance
Based on: Δwij = η · (xi · yj) · (α · EQ + β · IQ)
"""

import time
import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ContextEvent:
    """Context event for empathy measurement"""
    timestamp: float
    context_stability: float
    threat_level: float
    response_appropriateness: float

@dataclass
class FeedbackEvent:
    """Feedback event for accuracy measurement"""
    timestamp: float
    predicted_threat: float
    actual_threat: float
    accuracy: float

@dataclass
class EQIQBalance:
    """EQ/IQ balance result"""
    eq: float  # Emotional Intelligence (contextual empathy/stability)
    iq: float  # Intelligence Quotient (threat precision/accuracy)
    balance: float  # Normalized balance factor

class ExperientialBehavioralRegulator:
    """
    EQ/IQ Balanced Reward System for RHLS
    Implements experiential behavioral regulator with empathy (EQ) and accuracy (IQ) balance
    """
    
    def __init__(self, alpha: float = 0.6, beta: float = 0.4, learning_rate: float = 0.01):
        """
        Initialize the EQ/IQ regulator
        
        Args:
            alpha: EQ weight coefficient (α)
            beta: IQ weight coefficient (β)
            learning_rate: Learning rate (η)
        """
        self.alpha = alpha
        self.beta = beta
        self.learning_rate = learning_rate
        self.max_history = 1000
        
        # Historical context for empathy measurement
        self.context_history: List[ContextEvent] = []
        # Feedback accuracy tracking for IQ measurement
        self.feedback_history: List[FeedbackEvent] = []
    
    def measure_empathy(self, context: ContextEvent, history: List[ContextEvent]) -> float:
        """
        Measure empathy (EQ) based on contextual stability and benign response appropriateness
        
        Args:
            context: Current context event
            history: Historical context events
            
        Returns:
            EQ score (0.0 to 1.0)
        """
        if not history:
            return 0.5  # Neutral starting point
        
        # Calculate contextual stability over time
        stability_trend = self._calculate_stability_trend(history)
        
        # Measure benign contextual stability (higher is better for EQ)
        if context.threat_level < 0.3:
            benign_stability = context.context_stability * context.response_appropriateness
        else:
            # For high threat contexts, EQ is about measured, appropriate response
            benign_stability = context.response_appropriateness * (1.0 - min(context.threat_level, 0.8))
        
        # Combine with historical trend
        eq = np.clip(benign_stability * 0.7 + stability_trend * 0.3, 0.0, 1.0)
        
        logger.debug(f"EQ measurement: benign_stability={benign_stability:.3f}, "
                    f"stability_trend={stability_trend:.3f}, eq={eq:.3f}")
        
        return eq
    
    def measure_accuracy(self, feedback: FeedbackEvent) -> float:
        """
        Measure accuracy (IQ) based on threat prediction precision
        
        Args:
            feedback: Feedback event with prediction accuracy
            
        Returns:
            IQ score (0.0 to 1.0)
        """
        # Direct accuracy measurement from prediction vs reality
        prediction_error = abs(feedback.predicted_threat - feedback.actual_threat)
        base_accuracy = 1.0 - min(prediction_error, 1.0)
        
        # Enhance accuracy based on historical performance
        if len(self.feedback_history) > 5:
            recent_accuracies = [f.accuracy for f in self.feedback_history[-10:]]
            historical_accuracy = np.mean(recent_accuracies)
        else:
            historical_accuracy = base_accuracy
        
        iq = np.clip(base_accuracy * 0.6 + historical_accuracy * 0.4, 0.0, 1.0)
        
        logger.debug(f"IQ measurement: prediction_error={prediction_error:.3f}, "
                    f"base_accuracy={base_accuracy:.3f}, historical_accuracy={historical_accuracy:.3f}, "
                    f"iq={iq:.3f}")
        
        return iq
    
    def _calculate_stability_trend(self, history: List[ContextEvent]) -> float:
        """Calculate stability trend from historical context"""
        if len(history) < 2:
            return 0.5
        
        recent_events = history[-5:]  # Last 5 events
        stability_values = [e.context_stability for e in recent_events]
        
        # Calculate trend (positive = improving stability)
        trend_sum = 0.0
        for i in range(1, len(stability_values)):
            trend_sum += stability_values[i] - stability_values[i-1]
        
        trend = trend_sum / (len(stability_values) - 1)
        return np.clip(0.5 + trend, 0.0, 1.0)
    
    def calculate_eq_iq_balance(self, context: ContextEvent, feedback: FeedbackEvent) -> EQIQBalance:
        """
        Core EQ/IQ balanced reward calculation
        
        Args:
            context: Context event for EQ measurement
            feedback: Feedback event for IQ measurement
            
        Returns:
            EQIQBalance with eq, iq, and balance scores
        """
        # Add to history
        self.context_history.append(context)
        self.feedback_history.append(feedback)
        
        # Maintain history size
        if len(self.context_history) > self.max_history:
            self.context_history.pop(0)
        if len(self.feedback_history) > self.max_history:
            self.feedback_history.pop(0)
        
        # Calculate EQ and IQ
        eq = self.measure_empathy(context, self.context_history)
        iq = self.measure_accuracy(feedback)
        
        # Calculate balanced reward factor: α · EQ + β · IQ
        balance = self.alpha * eq + self.beta * iq
        
        logger.info(f"EQ/IQ Balance: EQ={eq:.3f} (α={self.alpha:.2f}), "
                   f"IQ={iq:.3f} (β={self.beta:.2f}), balance={balance:.3f}")
        
        return EQIQBalance(eq=eq, iq=iq, balance=balance)
    
    def bidirectional_hebbian_update(self, x_i: float, y_j: float, eq_weight: float, iq_weight: float) -> float:
        """
        Bidirectional Hebbian update with EQ/IQ balance
        Implements: Δwij = η · (xi · yj) · (α · EQ + β · IQ)
        
        Args:
            x_i: Pre-synaptic activation
            y_j: Post-synaptic activation
            eq_weight: EQ component weight
            iq_weight: IQ component weight
            
        Returns:
            Weight change (Δw)
        """
        eq_iq_balance = self.alpha * eq_weight + self.beta * iq_weight
        delta_w = self.learning_rate * (x_i * y_j) * eq_iq_balance
        
        logger.debug(f"Hebbian update: xi={x_i:.3f}, yj={y_j:.3f}, "
                    f"eq_iq_balance={eq_iq_balance:.3f}, Δw={delta_w:.3f}")
        
        return delta_w
    
    def adapt_parameters(self, performance_feedback: float):
        """
        Update regulator parameters based on performance
        
        Args:
            performance_feedback: Overall system performance (0.0 to 1.0)
        """
        # Adaptive parameter adjustment based on overall system performance
        if performance_feedback > 0.8:
            # High performance - maintain current balance
            return
        elif performance_feedback < 0.4:
            # Poor performance - adjust balance toward accuracy
            self.beta = min(self.beta * 1.1, 1.0)
            self.alpha = max(self.alpha * 0.95, 0.1)
        else:
            # Moderate performance - slight adjustment toward empathy
            self.alpha = min(self.alpha * 1.05, 1.0)
            self.beta = max(self.beta * 0.98, 0.1)
        
        # Normalize to ensure α + β ≈ 1.0
        total = self.alpha + self.beta
        self.alpha /= total
        self.beta /= total
        
        logger.info(f"Adapted EQ/IQ parameters: α={self.alpha:.3f}, β={self.beta:.3f}")
    
    def get_stats(self) -> Dict[str, float]:
        """Get current EQ/IQ statistics"""
        stats = {
            "alpha": self.alpha,
            "beta": self.beta,
            "learning_rate": self.learning_rate,
            "context_history_size": len(self.context_history),
            "feedback_history_size": len(self.feedback_history),
        }
        
        if self.context_history:
            avg_stability = np.mean([c.context_stability for c in self.context_history])
            stats["avg_context_stability"] = avg_stability
        
        if self.feedback_history:
            avg_accuracy = np.mean([f.accuracy for f in self.feedback_history])
            stats["avg_accuracy"] = avg_accuracy
        
        return stats