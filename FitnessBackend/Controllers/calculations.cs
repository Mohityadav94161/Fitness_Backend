using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Research.SEAL;
using System.Security.Cryptography.X509Certificates;
using PublicKey = Microsoft.Research.SEAL.PublicKey;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace FitnessBackend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class calculations : ControllerBase
    {


        EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
        public PublicKey PublicKey;
        public RelinKeys RelinKey;
        public GaloisKeys GaloisKey;
        public SEALContext context;
        CKKSEncoder encoder ;
        Encryptor encryptor ;
        Evaluator evaluator;


    double scale = Math.Pow(2.0, 40);
        static Plaintext p10 = new Plaintext();
        static Plaintext p100 = new Plaintext();
        static Plaintext p5 = new Plaintext();
        static Plaintext p625 = new Plaintext();
        static Plaintext p220 = new Plaintext();
        static Plaintext p60 = new Plaintext();


        [HttpPost]
        public outData Post([FromBody] calculationData request)
        {


            Console.WriteLine("post hit");

            //make ckksScheme 
         
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(polyModulusDegree, new int[] { 60, 40, 40, 60 });

            context = new SEALContext(parms);
            evaluator = new Evaluator(context);
            encoder = new CKKSEncoder(context);
            encryptor = new Encryptor(context, PublicKey);

           
            using PublicKey publicKey = new PublicKey();
            using RelinKeys relinKey = new RelinKeys();
            using GaloisKeys galoisKey = new GaloisKeys();
            using Ciphertext age = new Ciphertext();
            using Ciphertext weight = new Ciphertext();
            using Ciphertext height = new Ciphertext();
            using Ciphertext invHeight = new Ciphertext();
            using Ciphertext calories = new Ciphertext();
            using Ciphertext exerciseTime = new Ciphertext();

            // Load the byte arrays into the SEAL objects
            publicKey.Load(context, new MemoryStream(request.PublicKey));
            relinKey.Load(context, new MemoryStream(request.RelinKey));
            galoisKey.Load(context, new MemoryStream(request.GaloisKey));
            age.Load(context, new MemoryStream(request.Age));
            weight.Load(context, new MemoryStream(request.Weight));
            height.Load(context, new MemoryStream(request.Height));
            invHeight.Load(context, new MemoryStream(request.Inv_Height_2));
            calories.Load(context, new MemoryStream(request.Calories));
            exerciseTime.Load(context, new MemoryStream(request.ExerciseTime));

            Console.WriteLine(request);

           
        
            Ciphertext bmi = CalculateBMI(weight, invHeight);
            Ciphertext rmr = CalculateRMR(age, weight, height);
            Ciphertext targetHeartRate = CalculateTargetHeartRate(age);
            Ciphertext energyBalance = CalculateEnergyBalance(calories, rmr);
            Ciphertext exerciseIntensity = CalculateExerciseIntensity(exerciseTime);

            outData result = new outData();
            result.BMI = bmi;
            result.RMR = rmr;
            result.TargetHeartRate = targetHeartRate;
            result.EnergyBalance = energyBalance;
            result.ExerciseIntensity = exerciseIntensity;
            Console.WriteLine("final result is "+result);
          
            return result;
        }
        private Ciphertext CalculateBMI(Ciphertext weight, Ciphertext Inv_height_2)
        {
            Ciphertext r1 = new Ciphertext();
            Ciphertext res = new Ciphertext();

            evaluator.Multiply(weight, Inv_height_2, r1);
            evaluator.Relinearize(r1, RelinKey, res);

            //(weight * Inv_height_2);
            return res;
        }

        private Ciphertext CalculateRMR(Ciphertext age, Ciphertext weight, Ciphertext height)
        {
            Ciphertext c10 = new Ciphertext();
            Ciphertext c625 = new Ciphertext();
            Ciphertext c5 = new Ciphertext();

           

            encryptor.Encrypt(p10, c10);
            encryptor.Encrypt(p625, c625);
           // encryptor.Encrypt(p100, c100);
            encryptor.Encrypt(p5, c5);

            Ciphertext r1 = new Ciphertext();
            Ciphertext r2 = new Ciphertext();
            Ciphertext r3 = new Ciphertext();
            Ciphertext r4 = new Ciphertext();
            Ciphertext r5 = new Ciphertext();
            Ciphertext r6 = new Ciphertext();
            Ciphertext res = new Ciphertext();

            // 10*weight  ans store in c10
            evaluator.Multiply(c10, weight, r1);
            evaluator.Relinearize(r1, RelinKey, c10);

            //625*height ans store in c625
            evaluator.Multiply(c625,height, r2);
            evaluator.Relinearize(r2, RelinKey, c625);

            // 5*age  ans store in r6
            evaluator.Multiply(c5, age, r3);
            evaluator.Relinearize(r3, RelinKey, r6);

            // 10*weight +625*height (c10+c625) ans store in r4
            evaluator.Add(c10, c625, r4);

            //10 * weight + 6.25 * height * 100 - 5 * age (c10+c625+r6(5*age)) ans store in r5
            evaluator.Add(r4, r6, r5);

            //10 * weight + 6.25 * height * 100 - 5 * age + 5 (r5+c5) ans store in res
            evaluator.Add(r5, c5, res);

            //(10 * weight + 6.25 * height * 100 - 5 * age + 5)
            return res;
        }

        private Ciphertext CalculateTargetHeartRate(Ciphertext age)
        {
            Ciphertext c1 = new Ciphertext();
            Ciphertext res = new Ciphertext();

            //covert 220 into plaintext p220
            encoder.Encode(220, scale, p220);

            //create ciphertext from plaintext p220
            encryptor.Encrypt(p220, c1);

            //220-age
            evaluator.Sub(c1, age, res);

            //(220 - age);
            return res;

        }

        private Ciphertext CalculateEnergyBalance(Ciphertext calories, Ciphertext rmr)
        {
            Ciphertext res = new Ciphertext();
            //subtract calories,rmr
            evaluator.Sub(calories,rmr, res);

            //(calories - (rmr))
            return res;
            
        }

        private Ciphertext CalculateExerciseIntensity(Ciphertext exerciseTime)
        {
            //convert inv_60 into plaintext
            Plaintext p_inv_60 = new Plaintext();
            encoder.Encode(1 / 60, scale, p_inv_60);

            Ciphertext c1 = new Ciphertext();
            Ciphertext c2 = new Ciphertext();
            Ciphertext res = new Ciphertext();

            //convert plaintext inv_60 into ciphertext
            encryptor.Encrypt(p_inv_60, c1);

            // exercise*inv_60 ans store in c2
            evaluator.Multiply(c1, exerciseTime,c2);

            //ans store in res
            evaluator.Relinearize(c2, RelinKey, res);

            //(exerciseTime / 60)
            return res;
        }


       

    }
}
