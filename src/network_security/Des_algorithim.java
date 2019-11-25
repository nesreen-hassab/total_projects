/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network_security;

/**
 *
 * @author nesreen
 */
public class Des_algorithim 
{
    static byte[] initial_permute  ={58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};    
    static byte[] expansion_permute={32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
    static byte[][] sboxs ={
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
    static byte[] normal_permute={16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
    static byte[] final_permute ={40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
    
    static byte[] Permuted_choice1 ={57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
    static byte[] permuted_choice2 ={14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
    static byte[]sifttimes      ={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
   
    //static global variables 
    static String []subkey=new String[16];
    static String prevleft_k =" ";
    static String prevright_k=" ";
    static String newleft_k  =" ";
    static String newright_k =" ";
    static String newkey     =" ";
    
    static String prevleft_p =" ";
    static String prevright_p=" ";
    static String newleft_p  =" ";
    static String newright_p =" ";
    
    
    

    // permute function for key ,plaintext and ciphertext :
    public static String permute(String recieved ,byte []tables) 
    {
        StringBuilder builder =new StringBuilder();
        for(byte index : tables)
        {
            builder.append(recieved.charAt(index-1));
        }
        return builder.toString();
    }
    
    // shiftleft (rotate) function for key :
    public static String shiftleft(String prev, int times) 
    {
        return prev.substring(times)+prev.substring(0, times);
    }
    
    //subkeys function for generation keys :
    public static void Subkeys(String key)
    { 
        key =format(key);
        key=permute(key, Permuted_choice1);               //use permutedchoice1 for parity drop(64bit to 56bit)
        prevleft_k=key.substring(0, key.length()/2);        //global string variable
        prevright_k=key.substring(key.length()/2);          //global string variable
        for(int i=0 ;i<16 ;i++)
        {
            newleft_k=shiftleft(prevleft_k, sifttimes[i]);    //global string variable
            newright_k=shiftleft(prevright_k, sifttimes[i]);  //global string variable
            newkey=newleft_k+newright_k;                      //global string variable
            newkey=permute(newkey, permuted_choice2);     //use permutedchoice2 (56 bit  to 48 bit) 
            subkey[i]=newkey;                           //global arraylist to add on it
            prevleft_k=newleft_k;
            prevright_k=newright_k;
        }
    }
    
    //xor function :
    public static String xor(String one , String two)
    {
        long one2 ,two2 ,xored;
        String strxoed;
        one2=Long.parseLong(one, 2);
        two2=Long.parseLong(two, 2);
        xored=one2^two2;
        strxoed=Long.toBinaryString(xored);
        while(strxoed.length()<one.length())
        {
            strxoed='0'+strxoed;
        }
        return strxoed;
    }
    
    // sbox function :
      public static  String sbox (String newright )
    {
        //variables
        StringBuilder bulder =new StringBuilder();
        String bit1 ,bit6 ,sixbit;
        int twobit ,fourbit ,col ;
        String y=" ";
        
        //
        for(int i=0 ;i<48 ;i=i+6)
        {
            sixbit=newright.substring(i, i+6);
            bit1=sixbit.substring(0,1);
            bit6=sixbit.substring(5);
            twobit=Integer.parseInt((bit1+bit6), 2);            //number of row
            fourbit=Integer.parseInt(sixbit.substring(1, 5), 2);//number of column
            col=twobit*16+fourbit;                              //number of for finally sbox
            int value =sboxs[i/6][col];                         //get value from sbox
            y=Integer.toBinaryString(value);             //convert from integer to binary
            while(y.length()<4)
            {
                y="0"+y;
            }
           
           bulder.append(y);
        }
        
        return bulder.toString();
    }
    
    //function:
    public static void function(String key )
    {
        newright_p=permute(prevright_p,expansion_permute );
        newright_p=xor(newright_p, key);
        newright_p=sbox(newright_p);
        newright_p=permute(newright_p, normal_permute);
        newright_p=xor(newright_p, prevleft_p);
        
    }
    
    //formate text (convert from string to binary)
    public static String format(String text)
    {
        String name=text;
        StringBuilder bulder=new StringBuilder();
        for(int i=0 ;i<name.length() ;i++)
        {
            int convert=(int)(name.charAt(i));
            String n=Integer.toBinaryString(convert);
            while(n.length()<8)
            {
                n="0"+n;
            }
           bulder.append(n);
        }
        name=bulder.toString();
        return name;
     }
    
    //convert from binary to string
    public static String deformat(String text)
    {
        String name=text ;
        
        StringBuilder bulder=new StringBuilder();
        for(int i=0; i<name.length() ;i=i+8)
            {
                int x=Integer.parseInt(name.substring(i, i+8), 2);
                bulder.append((char)(x));
            }
        name =bulder.toString();
        return name ;
    }
    
           public static String encrypt(String plaintext ,String key)
    {
        String cipher=" " ;
        String plain =" ";
        Subkeys(key);
        plain=format(plaintext);
        plain=permute(plain,initial_permute);
        prevleft_p=plain.substring(0, plain.length()/2);
        prevright_p=plain.substring( plain.length()/2);
        for(int i=0 ; i<16 ;i++)
        {
            function(subkey[i]);
            newleft_p=prevright_p;
            prevleft_p=newleft_p;
            prevright_p=newright_p;
        }
        String temp;
        temp=newright_p;
        newright_p=newleft_p;
        newleft_p=temp;
        plain=newleft_p+newright_p;
        cipher=permute(plain, final_permute);
        cipher=deformat(cipher);
                
        return cipher;
    }
    // decript
    public static String decrypt(String ciphertext ,String key)
    {
        String plain=" " ;
        String cipher =" ";
        Subkeys(key);
        cipher=format(ciphertext);
        
        cipher=permute(cipher,initial_permute);
        prevleft_p=cipher.substring(0, cipher.length()/2);
        prevright_p=cipher.substring( cipher.length()/2);
        for(int i=15 ; i>=0 ;i--)
        {
            function(subkey[i]);
            newleft_p=prevright_p;
            prevleft_p=newleft_p;
            prevright_p=newright_p;
        }
        String temp;
        temp=newright_p;
        newright_p=newleft_p;
        newleft_p=temp;
        cipher=newleft_p+newright_p;
        plain=permute(cipher, final_permute);
        plain=deformat(plain);
                
        return plain;
    }
 
   
}
