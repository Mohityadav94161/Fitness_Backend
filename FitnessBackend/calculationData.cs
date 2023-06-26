using System.Security.Cryptography.X509Certificates;
using Microsoft.Research.SEAL;
using PublicKey = Microsoft.Research.SEAL.PublicKey;


namespace FitnessBackend
{
    public class calculationData
    {
        public byte[] Age { get; set; }
        public byte[] Weight { get; set; }
        public byte[] Height { get; set; }
        public byte[] Inv_Height_2 { get; set; }
        public byte[] Calories { get; set; }
        public byte[] ExerciseTime { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] RelinKey { get; set; }
        public byte[] GaloisKey { get; set; }
    }
    public class outData
    {
        public Ciphertext BMI { get; set; }
        public Ciphertext RMR { get; set; }
        public Ciphertext TargetHeartRate { get; set; }
        public Ciphertext EnergyBalance { get; set; }
        public Ciphertext ExerciseIntensity { get; set; }
    }
    public class CalculationResponse
    {
        public byte[] BMI { get; set; }
        public byte[] RMR { get; set; }
        public byte[] TargetHeartRate { get; set; }
        public byte[] EnergyBalance { get; set; }
        public byte[] ExerciseIntensity { get; set; }
    }
}
