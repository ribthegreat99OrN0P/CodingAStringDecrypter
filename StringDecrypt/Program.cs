using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Windows.Forms;
using dnlib.DotNet.Writer;
using System.IO;

namespace StringDecrypt
{
    class Program
    {
        static AssemblyDef asm;//More convenient than ModuleDefMD as if the assembly has many modules it will be perfect
        static string asmPath;//for later saving
        static int decryptCount = 0;//the number of strings decrypted
        static MethodDef decryptionMethodToRemove = null;//the method which decrypts the strings in the assembly
        static void Main(string[] args)
        {
            Console.Title = "Yano String Decrypter";
            try
            {
                if(args.Length == 0)//If user doesnt drag a file on the app create a dialogue for them to choose
                {
                    OpenFileDialog ofd = new OpenFileDialog();
                    ofd.Title = "Select a file";//Set the dialogue title
                    ofd.Filter = "Executable Files |*.exe";//Only shows files with the (.exe) extension. You can add many more
                    ofd.RestoreDirectory = true;//Restore the previous directory you were in when last using the dialogue
                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        asm = AssemblyDef.Load(ofd.FileName);//Load the exe
                        asmPath = ofd.FileName;//Set the path for later saving
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    asm = AssemblyDef.Load(args[0]);//Load the exe as the user dragged and dropped the exe onto the app
                    asmPath = args[0];//Set the path for later saving
                }
                
            }
            catch(Exception ex)//If something goes wrong loading the the program the issue will be written
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(string.Format("Looks like the file is either broken or not a valid PE file loading anyways:{0}", ex.Message));
            }
            StartDecryption();//Call the function to start the process


            ModuleWriterOptions opts = new ModuleWriterOptions(asm.ManifestModule);
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;//Preserve all tokens
            opts.Logger = DummyLogger.NoThrowInstance;//if their are any issues when saving it wont break the process instead it will continue
            asm.ManifestModule.Write(Path.GetFileNameWithoutExtension(asmPath) + "-strdecrypted.exe", opts);//save the decrypted string assembly 

            Console.WriteLine("Saved");
            Console.ReadKey();//Prevents the app from automatically closing after all the process is done waits till the user click any key
        }
        static void StartDecryption()
        {
            foreach(ModuleDef module in asm.Modules)//Loops/goes through all the modules in the Assembly
            {
                foreach(TypeDef type in module.GetTypes())// Loops/goes through all the types as well as the nested ones in the Assembly
                {
                    foreach(MethodDef method in type.Methods)//Loops/goes through all the methods
                    {
                        if(method.HasBody && method.Body.HasInstructions)//Checks to see if the method has a body with instructions in it
                        {
                            for (int i = 0; i < method.Body.Instructions.Count; i++)//Goes through all the instructions in the methodbody
                            {
                                if (method.Body.Instructions[i].OpCode == OpCodes.Ldstr && method.Body.Instructions[i + 1].IsLdcI4() &&
                                    method.Body.Instructions[i + 2].OpCode == OpCodes.Call)//This is where we determine where the encoded string is in the method and finds it
                                {
                                    var encodedString = method.Body.Instructions[i].Operand.ToString();//Gets the encoded string value
                                    var decryptionKey = method.Body.Instructions[i + 1].GetLdcI4Value();//Gets the key used to decrypt the encoded value
                                    decryptionMethodToRemove = ((MethodDef)method.Body.Instructions[i + 2].Operand);//Gets the call of the decryption method which we can later use to remove junk

                                    var decryptedString = decryptFunction(encodedString, decryptionKey);//uses the decryption function 
                                    if (decryptedString != null)//if the returned decrypted string is not null/nothing
                                    {
                                        method.Body.Instructions[i + 2].OpCode = OpCodes.Ldstr;//Replace the call method opcode to a string
                                        method.Body.Instructions[i + 2].Operand = decryptedString;//Replace the operand with the decoded string

                                        method.Body.Instructions[i].OpCode = OpCodes.Nop;//Nop the useless opcodes we dont need anymore
                                        method.Body.Instructions[i + 1].OpCode = OpCodes.Nop;//Nop the useless opcodes we dont need anymore

                                        decryptCount++;//adds 1 onto the count which tells us how many strings were successfully decrypted
                                    }
                                }
                            }
                        }                      
                    }
                }
            }
            //NOTE: this process of removing the junk is not always needed.
            TypeDef decryptionMethodType = decryptionMethodToRemove.DeclaringType;//Get the Type of the decryption call method we got before
            foreach(MethodDef method in decryptionMethodType.Methods.ToArray())//Loop/goes through all the methods in the type which contains the decryption method
            {
                if (method == decryptionMethodToRemove)//if a method is found we check if it is the same with the decryption method we got from before
                    decryptionMethodType.Methods.Remove(decryptionMethodToRemove);//if found remove/delete it

            }
            asm.ManifestModule.Types.Remove(decryptionMethodType);//This is not always the case, we remove this type because it contains NO methods or anything which affects the main code which is known as junk.
            Console.ForegroundColor = ConsoleColor.Green;         //If there are methods which will be high with other obfuscators leave it
            Console.WriteLine(string.Format("Decrypted {0} strings!", decryptCount));//Write the number of strings we decrypted
        }
        static string decryptFunction(string input, int key)//This decrypted function will not always be like this,
        {                                                   //in this example the decryption function is shown to us which we
            int num = 564162144 + key;                      // can easily copy(this is not the same case for many obfuscators)
            char[] array = input.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int num2 = i;
                char c = array[i];
                array[num2] = (char)((((c & 0xFF) ^ num++) << 8) | (byte)(((int)c >> 8) ^ num++));
            }
            return string.Intern(new string(array));
        }
    }
}
