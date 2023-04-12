using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;


namespace Program
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Генерація ключів
            using (var dsa = DSA.Create(2048))
            {
                var privateKey = dsa.ExportPkcs8PrivateKey();
                var publicKey = dsa.ExportSubjectPublicKeyInfo();

                // Збереження ключів у файл
                File.WriteAllBytes("private_key.pem", privateKey);
                File.WriteAllBytes("public_key.pem", publicKey);
            }

            // Приклад використання
            var paymentInfo = "Payment information";
            var orderInfo = "Order information";

            // Створення підпису для платіжної інформації
            var signaturePayment = SignData(paymentInfo, "private_key.pem");

            // Створення підпису для інформації про замовлення
            var signatureOrder = SignData(orderInfo, "private_key.pem");

            // Перевірка підпису для платіжної інформації
            var isPaymentValid = VerifySignature(paymentInfo, signaturePayment, "public_key.pem");

            // Перевірка підпису для інформації про замовлення
            var isOrderValid = VerifySignature(orderInfo, signatureOrder, "public_key.pem");

            // Виведення результатів перевірки підписів
            Console.WriteLine("Is payment signature valid? " + isPaymentValid);
            Console.WriteLine("Is order signature valid? " + isOrderValid);
        }

        static byte[] SignData(string data, string privateKeyPath)
        {
            // Завантаження приватного ключа з файлу
            var privateKey = File.ReadAllBytes(privateKeyPath);

            // Створення хешу повідомлення
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));

            // Підпис повідомлення
            using (var dsa = DSA.Create())
            {
                dsa.ImportPkcs8PrivateKey(privateKey, out _);
                var signature = dsa.SignHash(hash);
                return signature;
            }
        }

        static bool VerifySignature(string data, byte[] signature, string publicKeyPath)
        {
            // Завантаження публічного ключа з файлу
            var publicKey = File.ReadAllBytes(publicKeyPath);

            // Створення хешу повідомлення
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));

            // Перевірка підпису
            using (var dsa = DSA.Create())
            {
                dsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                return dsa.VerifyHash(hash, signature);
            }
        }
    }
}
