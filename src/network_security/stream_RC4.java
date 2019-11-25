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
public class stream_RC4 
{
    static int s[]=new int[256];
    static int k[]=new int[256];
    
    //initialization :
    public static void initialization(String key)
    {
        for(int i=0; i<256 ;i++)
        {
            s[i]=i;
            k[i]=key.charAt(i%key.length());
        }
        //swap s
        int j=0;
        for(int i=0; i<256 ;i++)
        {
            j=(j+s[i]+k[i])%256;
            int t=s[i];
            s[i]=s[j];
            s[j]=t;
        }
    }
    //generat key :
    public static void key_generates() 
    {
        int i=0,j=0;
        for(int n=0 ;n<256 ;n++)
        {  
            i=(i+1)% 256;
            j=(j+s[i])% 256;
            int t=s[i];
            s[i]=s[j];
            s[j]=t;
            k[n]=(char)(s[(s[i]+s[j])% 256]);
        }
    }
    //key formate
    public static String key_formate()
    {
        StringBuilder bulder=new StringBuilder();
        for(int i=0 ;i<256 ;i++)
        {
            int n=k[i];
            String s=Integer.toBinaryString(n);
                while(s.length()<8)
                {
                    s="0"+s;
                }
               bulder.append(s);
        }  
        return bulder.toString();
   }
     // convert from string to binary :  
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
    // convert from binary to string
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
    // encripte
    public static String encript(String text,String keytext) 
    {
        initialization(keytext);
        key_generates();
        String key   =key_formate();
        String plain =format(text);
        String cipher =""; 
        String subkey ,subplain; 
        for(int i=0 ;i< plain.length() ;i=i+8)
        {
            subkey   =key.substring( i%256 , (i+8)%256);
            subplain =plain.substring(i, i+8);
            for(int j=0 ; j< 8 ; j++)
            {
                cipher=cipher+(subplain.charAt(j)^subkey.charAt(j));
            }
        }
        cipher=deformat(cipher);
                
        return cipher;
  }
    // decripte
    public static String decript(String text,String keytext) 
    {
        initialization(keytext);
        key_generates();
        String key   =key_formate();
        String cipher =format(text);
        String plain =""; 
        String subkey ,subcipher; 
        for(int i=0 ;i< cipher.length() ;i=i+8)
        {
            subkey   =key.substring( i%256 , (i+8)%256);
            subcipher =cipher.substring(i, i+8);
            for(int j=0 ; j< 8 ; j++)
            {
                plain=plain+(subcipher.charAt(j)^subkey.charAt(j));
            }
        }
        plain=deformat(plain);
        return plain;
  }
   
    
}
