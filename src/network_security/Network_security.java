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
public class Network_security {

   
    /**
     * @param args the command line arguments
     */
    // ---encription function--- 
     
     
    public static String encription(String p,int k)
     {
         String c=" ";
         char x;
         for(int i=0;i<p.length();i++)
        {
            if(p.charAt(i)!=' ')
             {
                x=(char)(p.charAt(i)+k);
                if (x>'z')
                {
                    x=(char)(x-26);                                                                                                             //(p.charAt(i)+k-26);
                }
                c+=x;
             }
         }
         return c;
     }
     
     //---decription function--- 
     public static String decription(String cipher,int key)
     {
         String plain=" ";
         char x;
         for(int i=0;i<cipher.length();i++)
         {
              if(cipher.charAt(i)!=' ')
             {
                x=(char)(cipher.charAt(i)-key);
                if(x<'a')
                {
                    x=(char)(x+26);                                                                                          //(cipher.charAt(i)-key+26);
                }
                plain+=x;
             }
         }
         return plain;
     } 
     
     
     
}