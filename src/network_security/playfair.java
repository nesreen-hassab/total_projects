/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network_security;

import java.util.ArrayList;

/**
 *
 * @author nesreen
 */
public class playfair 
{
    //format plaintext to encript 
    public static String format(String plaintext)
    {
        StringBuilder temp =new StringBuilder();
        for(int i=0 ; i<plaintext.length() ; i++)
        {
            if(plaintext.charAt(i) != ' ')
            {
                if(plaintext.charAt(i)=='j')
                {
                    temp.append('i');
                }
                else
                    temp.append(plaintext.charAt(i));
            }
        }
        // to put x between the similar characters
        for(int i=0 ; i<plaintext.length() ; i=i+2)
        {
            if(temp.charAt(i)==temp.charAt(i+1))
            {
                temp.insert(i+1, 'x');
            }
        }
        plaintext=temp.toString();
        //to put x back the word if odd
        if(plaintext.length()%2==1)
        {
            plaintext=plaintext+'x';
        }
        return plaintext ;
    }
    
    //divide plaintext to two letters together
    public static String[] divide_plaintext_to(String plain)
    {
        String plaintext=format(plain);
        String []x=new String[plaintext.length()/2];
        int c=0;
        for(int i=0 ; i<x.length ; i++)
        {
            x[i]=plaintext.substring(c, c+2);
            c+=2;
        }
        return x;
    }
    
    //adjust key
    
    public static String Adjusted (String key ) 
    {
        String alphapet ="abcdefghijklmnopqrstuvwxyz";
        String keyalpha =key+alphapet;
        char []c=keyalpha.toCharArray();
        ArrayList<Character> adjusted =new ArrayList<>();
        for(char x : c )
        {
            if(x=='j')   x='i';
            if(!adjusted.contains(x))
            {
                adjusted.add(x);
            }
        }
        
        String list=adjusted.toString();
        StringBuilder temp=new StringBuilder();
        for(int i=0; i<list.length() ;i++)
        {
            if(list.charAt(i)=='['||list.charAt(i)==']'||list.charAt(i)==' '||list.charAt(i)==',')
            {
                
            }
            else temp.append(list.charAt(i));
        }
        list=temp.toString();
        return list;
    }
    
    
    //put letters in matrix 5*5
    public static char[][] matrix (String key)
    {
        String keyalpha=Adjusted(key);
        char [][]matrix=new char[5][5];
        int c=0;
        for(int i=0; i<5;i++)
        {
            for(int j=0 ; j<5 ;j++)
            {
                matrix[i][j]=keyalpha.charAt(c);
                c++;
                
            }
        }
        return matrix;
    }
    //finally encript
    public static String encript(String plaintext,String key)
    {
        String ciphertext="";
        StringBuilder temp =new StringBuilder();
        String []plain =divide_plaintext_to(plaintext);
        char [][] matrx=matrix(key);
        char a,b,ciphera,cipherb;
        int rowa=0,rowb=0, columna=0,columnb=0;
        for( String x:plain)
        {
             a=x.charAt(0);
             b=x.charAt(1);
            
            for(int i=0; i<5;i++)
            {
                for(int j=0 ; j<5 ;j++)
                {
                    if(a==matrx[i][j])
                    {
                         rowa=i;
                         columna=j;
                    }
                    if(b==matrx[i][j])
                    {
                         rowb=i;
                         columnb=j;
                    }
                }
            }
            
            if(rowa==rowb)
            {     
                if(columna==4)
                {
                    ciphera=matrx[rowa][0];
                    cipherb=matrx[rowb][columnb+1]; 
                }
                else if(columnb==4)
                {
                    ciphera=matrx[rowa][columna+1];
                    cipherb= matrx[rowb][0]; 
                }
                else 
                {
                    ciphera=matrx[rowa][columna+1];
                    cipherb= matrx[rowb][columnb+1];
                }
            }
            else if(columna==columnb)
            {      
                if(rowa==4)
                {
                   ciphera=matrx[0][columna];
                   cipherb=matrx[rowb+1][columnb]; 
                }
                else if(rowb==4)
                {
                   ciphera=matrx[rowa+1][columna];
                   cipherb= matrx[0][columnb]; 
                }
                else 
                {
                    ciphera=matrx[rowa+1][columna];
                    cipherb= matrx[rowb+1][columnb];
                }
            }
            else 
            {       
                ciphera=matrx[rowa][columnb];
                cipherb=matrx[rowb][columna];
            }
            
            temp.append(ciphera);
            temp.append(cipherb);
        }
         
         ciphertext=temp.toString();
        
         
        return ciphertext;
    }
    
    
    
    //decription part
    public static String[] divide_ciphertext_to(String cipher)
    {
        String []x=new String[cipher.length()/2];
        int c=0;
        for(int i=0 ; i<x.length ; i++)
        {
            x[i]=cipher.substring(c, c+2);
            c+=2;
        }
        return x;
    }
    
    public static String decript(String ciphertext,String key)
    {
        String plaintext="";
        StringBuilder temp =new StringBuilder();
        String []cipher =playfair.divide_ciphertext_to(ciphertext);
        char [][] matrx=playfair.matrix(key);
        char a,b,plaina,plainb;
        int rowa=0,rowb=0, columna=0,columnb=0;
        for( String x:cipher)
        {
             a=x.charAt(0);
             b=x.charAt(1);
            
            for(int i=0; i<5;i++)
            {
                for(int j=0 ; j<5 ;j++)
                {
                    if(a==matrx[i][j])
                    {
                         rowa=i;
                         columna=j;
                    }
                    if(b==matrx[i][j])
                    {
                         rowb=i;
                         columnb=j;
                    }
                }
            }
            
            if(rowa==rowb)
            {     
                if(columna==0)
                {
                    plaina=matrx[rowa][4];
                    plainb=matrx[rowb][columnb-1]; 
                }
                else if(columnb==0)
                {
                    plaina=matrx[rowa][columna-1];
                    plainb= matrx[rowb][4]; 
                }
                else 
                {
                    plaina=matrx[rowa][columna-1];
                    plainb= matrx[rowb][columnb-1];
                }
            }
            else if(columna==columnb)
            {      
                if(rowa==0)
                {
                   plaina=matrx[4][columna];
                   plainb=matrx[rowb-1][columnb]; 
                }
                else if(rowb==0)
                {
                   plaina=matrx[rowa-1][columna];
                   plainb= matrx[4][columnb]; 
                }
                else 
                {
                    plaina=matrx[rowa-1][columna];
                    plainb= matrx[rowb-1][columnb];
                }
            }
            else 
            {       
                plaina=matrx[rowa][columnb];
                plainb=matrx[rowb][columna];
            }
            
            temp.append(plaina);
            temp.append(plainb);
        }
         
         plaintext=temp.toString();
        
         
        return plaintext;
    }
    
    
}
