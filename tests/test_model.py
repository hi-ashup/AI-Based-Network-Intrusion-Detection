import unittest
import sys
import os

# Add the parent directory to path so we can import 'src'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.engine import NIDSEngine

class TestNIDSEngine(unittest.TestCase):
    
    def setUp(self):
        """Runs before every test. Sets up a fresh engine."""
        self.engine = NIDSEngine()

    def test_data_generation(self):
        """Check if data is generated correctly."""
        print("\nTesting Data Generation...")
        self.assertFalse(self.engine.df.empty, "Dataframe should not be empty")
        self.assertIn('Label', self.engine.df.columns, "Dataframe must have a 'Label' column")

    def test_model_training(self):
        """Check if the model trains without crashing."""
        print("Testing Model Training...")
        self.engine.train(split_ratio=80, trees=10) # Low tree count for fast testing
        self.assertIsNotNone(self.engine.model, "Model should not be None after training")

    def test_prediction_logic(self):
        """Check if the model can make a prediction."""
        print("Testing Prediction Logic...")
        self.engine.train(split_ratio=80, trees=10)
        
        # Test a safe packet input
        # [Duration, Packets, Length, Active]
        safe_input = [5000, 5, 500, 10] 
        result = self.engine.predict_single(safe_input)
        
        self.assertIn(result, [0, 1], "Prediction should be 0 (Safe) or 1 (Malicious)")

if __name__ == '__main__':
    unittest.main()