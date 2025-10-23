"""
TinyLLaMA + BHSM Integration System
==================================

This system demonstrates how BHSM components (CMNN, BDHMemory, PSI) can complement
TinyLLaMA to overcome context window constraints through experiential memory growth
and synaptic memory mechanisms.

Key Innovation: Hybrid architecture where:
- TinyLLaMA handles language understanding and generation
- PSI provides persistent semantic memory beyond context window
- BDH learns from interactions and adapts over time
- CMNN coordinates between components and provides meta-reasoning
- Memory bridge translates between LLM and BHSM representations

(c) 2025 - Shane D. Shook, All Rights Reserved
"""

import time
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from transformers import AutoTokenizer, AutoModelForCausalLM
from typing import Dict, List, Tuple, Optional, Any
import json
import hashlib
from datetime import datetime
from collections import deque
import matplotlib.pyplot as plt

# Import BHSM components
from BHSM import (
    PSIIndex, BDHMemory, CognitiveMesh, SimEmbedder,
    l2_norm, sim_cos, EMBED_DIM, DEVICE
)

# Configuration
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

# TinyLLaMA Configuration
MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
MAX_CONTEXT_LENGTH = 2048  # TinyLLaMA's context window
MEMORY_RETRIEVAL_K = 5     # Number of memories to retrieve
LEARNING_RATE = 1e-4

class MemoryBridge:
    """
    Bridge between TinyLLaMA representations and BHSM memory systems.
    
    This component translates between:
    - LLM token embeddings and BHSM semantic vectors
    - Text conversations and structured memory entries
    - LLM attention patterns and BHSM relevance scores
    """
    
    def __init__(self, llm_embed_dim: int = 2048, bhsm_embed_dim: int = EMBED_DIM):
        self.llm_embed_dim = llm_embed_dim
        self.bhsm_embed_dim = bhsm_embed_dim
        self.embedder = SimEmbedder(bhsm_embed_dim)
        
        # Neural bridge for embedding translation
        self.bridge_net = nn.Sequential(
            nn.Linear(llm_embed_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Linear(256, bhsm_embed_dim)
        ).to(DEVICE)
        
        self.bridge_optimizer = optim.Adam(self.bridge_net.parameters(), lr=LEARNING_RATE)
        
    def text_to_bhsm_embedding(self, text: str) -> np.ndarray:
        """Convert text to BHSM-compatible embedding."""
        return self.embedder.embed(text)
    
    def llm_hidden_to_bhsm(self, llm_hidden: torch.Tensor) -> np.ndarray:
        """Convert LLM hidden states to BHSM embedding space."""
        with torch.no_grad():
            bhsm_embed = self.bridge_net(llm_hidden.to(DEVICE))
            return l2_norm(bhsm_embed.cpu().numpy())
    
    def create_memory_entry(self, text: str, context: str, response: str, 
                          reward: float = 0.0) -> Dict:
        """Create a structured memory entry from conversation."""
        return {
            "text": text,
            "context": context,
            "response": response,
            "embedding": self.text_to_bhsm_embedding(text),
            "reward": reward,
            "timestamp": time.time(),
            "id": hashlib.md5(f"{text}_{time.time()}".encode()).hexdigest()[:8]
        }

class ExperientialMemorySystem:
    """
    Experiential memory system that grows beyond context window constraints.
    
    Components:
    - PSI: Long-term semantic memory for facts, patterns, and experiences
    - BDH: Adaptive learning from successful/unsuccessful interactions
    - Episode buffer: Recent conversation history with reward signals
    """
    
    def __init__(self):
        self.psi = PSIIndex()
        self.bdh_episodic = BDHMemory("episodic")
        self.bdh_semantic = BDHMemory("semantic")
        self.episode_buffer = deque(maxlen=100)
        self.memory_stats = {"retrievals": 0, "consolidations": 0, "adaptations": 0}
        
        # Initialize with foundational knowledge
        self._initialize_foundational_memories()
    
    def _initialize_foundational_memories(self):
        """Initialize system with foundational knowledge and patterns."""
        foundational_knowledge = [
            ("greeting", "Hello, how can I help you today?", 0.5),
            ("explanation", "I can explain concepts and answer questions", 0.5),
            ("learning", "I learn from our conversations to improve", 0.5),
            ("memory", "I remember important information from our chats", 0.5),
            ("context", "I can maintain context across long conversations", 0.5)
        ]
        
        embedder = SimEmbedder()
        for topic, text, valence in foundational_knowledge:
            self.psi.add_doc(
                f"foundation_{topic}",
                text,
                embedder.embed(text),
                tags=["foundation", topic],
                valence=valence,
                protected=True
            )
    
    def store_experience(self, memory_entry: Dict):
        """Store a new experience in the memory system."""
        # Add to episode buffer
        self.episode_buffer.append(memory_entry)
        
        # Store in PSI for long-term retrieval
        self.psi.add_doc(
            memory_entry["id"],
            memory_entry["text"],
            memory_entry["embedding"],
            tags=["conversation", "experience"],
            valence=memory_entry["reward"]
        )
        
        # Store in BDH for adaptive learning
        self.bdh_episodic.add_or_update(
            memory_entry["id"],
            memory_entry["embedding"],
            valence=memory_entry["reward"]
        )
        
        # Update BDH with reward signal if available
        if memory_entry["reward"] != 0.0:
            self.bdh_episodic.reward_gated_update(
                memory_entry["id"],
                memory_entry["embedding"],
                memory_entry["reward"]
            )
            self.memory_stats["adaptations"] += 1
    
    def retrieve_relevant_memories(self, query_text: str, k: int = MEMORY_RETRIEVAL_K) -> List[Dict]:
        """Retrieve relevant memories for the current query."""
        embedder = SimEmbedder()
        query_embedding = embedder.embed(query_text)
        
        # Search PSI for semantic matches
        psi_results = self.psi.search(query_embedding, top_k=k)
        
        # Search BDH for experiential matches
        bdh_results = self.bdh_episodic.retrieve_similar(query_embedding, top_k=k)
        
        # Combine and rank results
        all_results = []
        
        # Add PSI results
        for score, doc_id, entry in psi_results:
            all_results.append({
                "source": "psi",
                "score": score,
                "text": entry["text"],
                "valence": entry["valence"],
                "tags": entry["tags"]
            })
        
        # Add BDH results
        for score, trace_id, entry in bdh_results:
            all_results.append({
                "source": "bdh",
                "score": score,
                "text": f"Experience: {trace_id}",
                "valence": entry["valence"],
                "uses": entry["uses"]
            })
        
        # Sort by score and return top k
        all_results.sort(key=lambda x: x["score"], reverse=True)
        self.memory_stats["retrievals"] += 1
        
        return all_results[:k]
    
    def consolidate_memories(self):
        """Consolidate important memories from episode buffer to long-term storage."""
        if len(self.episode_buffer) < 10:
            return
        
        # Find high-value experiences
        high_value_episodes = [
            ep for ep in self.episode_buffer 
            if abs(ep["reward"]) > 0.5
        ]
        
        for episode in high_value_episodes:
            # Promote to semantic memory if highly valued
            if episode["reward"] > 0.7:
                self.bdh_semantic.add_or_update(
                    f"semantic_{episode['id']}",
                    episode["embedding"],
                    valence=episode["reward"],
                    protected=True
                )
                self.memory_stats["consolidations"] += 1
    
    def get_memory_summary(self) -> Dict:
        """Get summary of memory system state."""
        return {
            "psi_stats": self.psi.get_stats(),
            "episode_buffer_size": len(self.episode_buffer),
            "memory_stats": self.memory_stats,
            "bdh_episodic_size": len(self.bdh_episodic.storage),
            "bdh_semantic_size": len(self.bdh_semantic.storage)
        }

class TinyLLaMABHSMSystem:
    """
    Main integration system combining TinyLLaMA with BHSM components.
    
    This system demonstrates how to extend LLM capabilities with:
    - Persistent memory beyond context window
    - Experiential learning and adaptation
    - Meta-cognitive reasoning through CMNN
    """
    
    def __init__(self, model_name: str = MODEL_NAME):
        print(f"Initializing TinyLLaMA + BHSM System...")
        
        # Initialize TinyLLaMA
        print("Loading TinyLLaMA model...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            device_map="auto" if torch.cuda.is_available() else None
        )
        
        # Add padding token if not present
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Initialize BHSM components
        print("Initializing BHSM components...")
        self.memory_bridge = MemoryBridge()
        self.experiential_memory = ExperientialMemorySystem()
        self.cognitive_mesh = CognitiveMesh().to(DEVICE)
        
        # Conversation state
        self.conversation_history = []
        self.context_window = deque(maxlen=MAX_CONTEXT_LENGTH // 50)  # Approximate token management
        
        print("System initialization complete!")
    
    def _format_memories_for_context(self, memories: List[Dict]) -> str:
        """Format retrieved memories for inclusion in LLM context."""
        if not memories:
            return ""
        
        memory_text = "\n[Relevant memories from past conversations:]\n"
        for i, memory in enumerate(memories[:3]):  # Limit to top 3 to save context
            memory_text += f"- {memory['text']} (relevance: {memory['score']:.2f})\n"
        memory_text += "[End of memories]\n\n"
        
        return memory_text
    
    def _calculate_response_reward(self, user_input: str, response: str) -> float:
        """
        Calculate reward signal for the response.
        
        This is a simplified reward function. In practice, this could be based on:
        - User feedback (thumbs up/down)
        - Task completion success
        - Conversation flow quality
        - Factual accuracy
        """
        # Simple heuristics for demonstration
        reward = 0.0
        
        # Positive signals
        if len(response) > 20 and len(response) < 500:  # Appropriate length
            reward += 0.2
        if any(word in response.lower() for word in ["help", "understand", "explain"]):
            reward += 0.3
        if "?" in user_input and len(response) > 30:  # Good response to question
            reward += 0.3
        
        # Negative signals
        if len(response) < 10:  # Too short
            reward -= 0.3
        if response.count("I don't know") > 1:  # Excessive uncertainty
            reward -= 0.2
        
        return np.clip(reward, -1.0, 1.0)
    
    def generate_response(self, user_input: str, use_memory: bool = True) -> Tuple[str, Dict]:
        """
        Generate response using TinyLLaMA enhanced with BHSM memory.
        
        Args:
            user_input: User's input text
            use_memory: Whether to use BHSM memory enhancement
            
        Returns:
            Tuple of (response_text, metadata)
        """
        start_time = time.time()
        metadata = {"memory_used": use_memory, "memories_retrieved": 0}
        
        # Retrieve relevant memories if enabled
        memory_context = ""
        if use_memory:
            memories = self.experiential_memory.retrieve_relevant_memories(user_input)
            memory_context = self._format_memories_for_context(memories)
            metadata["memories_retrieved"] = len(memories)
        
        # Construct prompt with memory context
        conversation_context = "\n".join([
            f"User: {turn['user']}\nAssistant: {turn['assistant']}" 
            for turn in list(self.context_window)[-3:]  # Last 3 turns
        ])
        
        prompt = f"""You are a helpful AI assistant with access to memory from past conversations.

{memory_context}{conversation_context}

User: {user_input}
Assistant:"""
        
        # Generate response with TinyLLaMA
        inputs = self.tokenizer(
            prompt, 
            return_tensors="pt", 
            truncation=True, 
            max_length=MAX_CONTEXT_LENGTH - 200  # Leave room for generation
        )
        
        with torch.no_grad():
            outputs = self.model.generate(
                inputs.input_ids,
                max_new_tokens=150,
                temperature=0.7,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id,
                attention_mask=inputs.attention_mask
            )
        
        # Decode response
        full_response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        response = full_response[len(prompt):].strip()
        
        # Calculate reward and store experience
        reward = self._calculate_response_reward(user_input, response)
        
        memory_entry = self.memory_bridge.create_memory_entry(
            text=f"Q: {user_input} A: {response}",
            context=conversation_context,
            response=response,
            reward=reward
        )
        
        self.experiential_memory.store_experience(memory_entry)
        
        # Update conversation history
        self.conversation_history.append({
            "user": user_input,
            "assistant": response,
            "reward": reward,
            "timestamp": time.time()
        })
        
        self.context_window.append({
            "user": user_input,
            "assistant": response
        })
        
        # Periodic memory consolidation
        if len(self.conversation_history) % 10 == 0:
            self.experiential_memory.consolidate_memories()
        
        metadata.update({
            "reward": reward,
            "generation_time": time.time() - start_time,
            "memory_summary": self.experiential_memory.get_memory_summary()
        })
        
        return response, metadata
    
    def chat_session(self, max_turns: int = 20):
        """
        Interactive chat session demonstrating context window extension.
        """
        print("\n" + "="*60)
        print("TinyLLaMA + BHSM Chat Session")
        print("Demonstrating context window extension through experiential memory")
        print("="*60)
        print("Type 'quit' to exit, 'memory' to see memory stats, 'compare' to compare with/without memory")
        print()
        
        turn_count = 0
        while turn_count < max_turns:
            try:
                user_input = input(f"\n[Turn {turn_count + 1}] You: ").strip()
                
                if user_input.lower() == 'quit':
                    break
                elif user_input.lower() == 'memory':
                    self._show_memory_stats()
                    continue
                elif user_input.lower() == 'compare':
                    self._compare_responses(input("Enter question for comparison: "))
                    continue
                elif not user_input:
                    continue
                
                # Generate response with memory
                response, metadata = self.generate_response(user_input, use_memory=True)
                
                print(f"\nAssistant: {response}")
                print(f"\n[Metadata: Reward={metadata['reward']:.2f}, "
                      f"Memories={metadata['memories_retrieved']}, "
                      f"Time={metadata['generation_time']:.2f}s]")
                
                turn_count += 1
                
            except KeyboardInterrupt:
                print("\n\nChat session interrupted.")
                break
            except Exception as e:
                print(f"\nError: {e}")
                continue
        
        print(f"\nChat session completed after {turn_count} turns.")
        self._show_final_summary()
    
    def _show_memory_stats(self):
        """Display current memory system statistics."""
        summary = self.experiential_memory.get_memory_summary()
        print("\n" + "="*40)
        print("MEMORY SYSTEM STATISTICS")
        print("="*40)
        print(f"PSI Documents: {summary['psi_stats']['total_docs']}")
        print(f"Protected Documents: {summary['psi_stats']['protected_docs']}")
        print(f"Positive Memories: {summary['psi_stats']['positive_valence']}")
        print(f"Negative Memories: {summary['psi_stats']['negative_valence']}")
        print(f"Episode Buffer: {summary['episode_buffer_size']}")
        print(f"BDH Episodic: {summary['bdh_episodic_size']}")
        print(f"BDH Semantic: {summary['bdh_semantic_size']}")
        print(f"Total Retrievals: {summary['memory_stats']['retrievals']}")
        print(f"Consolidations: {summary['memory_stats']['consolidations']}")
        print(f"Adaptations: {summary['memory_stats']['adaptations']}")
        print("="*40)
    
    def _compare_responses(self, question: str):
        """Compare responses with and without memory enhancement."""
        print(f"\nComparing responses for: '{question}'")
        print("\n" + "-"*50)
        
        # Response without memory
        print("WITHOUT MEMORY:")
        response_no_mem, meta_no_mem = self.generate_response(question, use_memory=False)
        print(response_no_mem)
        
        print("\n" + "-"*50)
        
        # Response with memory
        print("WITH MEMORY:")
        response_with_mem, meta_with_mem = self.generate_response(question, use_memory=True)
        print(response_with_mem)
        
        print(f"\nMemories retrieved: {meta_with_mem['memories_retrieved']}")
        print("-"*50)
    
    def _show_final_summary(self):
        """Show final session summary."""
        print("\n" + "="*60)
        print("SESSION SUMMARY")
        print("="*60)
        
        if self.conversation_history:
            avg_reward = np.mean([turn["reward"] for turn in self.conversation_history])
            print(f"Total turns: {len(self.conversation_history)}")
            print(f"Average reward: {avg_reward:.3f}")
            
            # Show reward trend
            rewards = [turn["reward"] for turn in self.conversation_history]
            if len(rewards) > 1:
                trend = "improving" if rewards[-1] > rewards[0] else "declining"
                print(f"Reward trend: {trend}")
        
        self._show_memory_stats()
        print("="*60)

def demonstrate_context_extension():
    """
    Demonstration of how BHSM extends TinyLLaMA's context window.
    """
    print("="*80)
    print("CONTEXT WINDOW EXTENSION DEMONSTRATION")
    print("="*80)
    
    # Initialize system
    system = TinyLLaMABHSMSystem()
    
    # Simulate a long conversation that exceeds context window
    long_conversation = [
        "Hi, I'm working on a machine learning project about image classification.",
        "Can you explain what convolutional neural networks are?",
        "That's helpful! Now I'm curious about transfer learning.",
        "I'm using PyTorch for my implementation. Any tips?",
        "Great! Now I need to understand data augmentation techniques.",
        "What about regularization methods like dropout?",
        "I'm also interested in learning rate scheduling.",
        "Can you explain the Adam optimizer?",
        "Now I want to learn about model evaluation metrics.",
        "What's the difference between precision and recall?",
        "I'm having trouble with overfitting. Any suggestions?",
        "Can you remind me what we discussed about convolutional neural networks earlier?"
    ]
    
    print("Simulating long conversation that exceeds TinyLLaMA's context window...")
    print("The system should remember early topics even when they're out of context.\n")
    
    for i, user_input in enumerate(long_conversation):
        print(f"\n[Turn {i+1}] User: {user_input}")
        
        response, metadata = system.generate_response(user_input)
        print(f"Assistant: {response}")
        
        if metadata["memories_retrieved"] > 0:
            print(f"[Used {metadata['memories_retrieved']} memories from past conversation]")
        
        # Show memory growth
        if i % 3 == 0:
            summary = system.experiential_memory.get_memory_summary()
            print(f"[Memory: {summary['psi_stats']['total_docs']} docs, "
                  f"{summary['bdh_episodic_size']} experiences]")
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print("Notice how the system:")
    print("1. Remembers information from early in the conversation")
    print("2. Builds up experiential memory over time")
    print("3. Retrieves relevant memories to inform responses")
    print("4. Adapts based on conversation success (reward signals)")
    print("="*80)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TinyLLaMA + BHSM Integration System")
    parser.add_argument("--mode", choices=["chat", "demo"], default="demo",
                       help="Run interactive chat or demonstration")
    parser.add_argument("--max-turns", type=int, default=20,
                       help="Maximum turns for chat session")
    
    args = parser.parse_args()
    
    if args.mode == "chat":
        system = TinyLLaMABHSMSystem()
        system.chat_session(max_turns=args.max_turns)
    else:
        demonstrate_context_extension()