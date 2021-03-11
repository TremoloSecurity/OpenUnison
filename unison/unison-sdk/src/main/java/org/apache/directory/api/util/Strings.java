/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.util;


import static org.apache.directory.api.util.Chars.isHex;
import static org.apache.directory.api.util.Hex.encodeHex;
import static org.apache.directory.api.util.Hex.getHexValue;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.directory.api.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Various string manipulation methods that are more efficient then chaining
 * string operations: all is done in the same buffer without creating a bunch of
 * string objects.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Strings
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( Strings.class );

    /** The default charset, because it's not provided by JDK 1.5 */
    static String defaultCharset = null;

    /** Hex chars */
    private static final byte[] HEX_CHAR = new byte[]
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /** A table containing booleans when the corresponding char is printable */
    public static final boolean[] IS_PRINTABLE_CHAR =
        {
            false, false, false, false, false, false, false, false, // ---, ---, ---, ---, ---, ---, ---, ---
            false, false, false, false, false, false, false, false, // ---, ---, ---, ---, ---, ---, ---, ---
            false, false, false, false, false, false, false, false, // ---, ---, ---, ---, ---, ---, ---, ---
            false, false, false, false, false, false, false, false, // ---, ---, ---, ---, ---, ---, ---, ---
            true,  false, false, false, false, false, false, true,  // ' ', ---, ---, ---, ---, ---, ---, "'"
            true,  true,  false, true,  true,  true,  true,  true,  // '(', ')', ---, '+', ',', '-', '.', '/'
            true,  true,  true,  true,  true,  true,  true,  true,  // '0', '1', '2', '3', '4', '5', '6', '7',
            true,  true,  true,  false, false, true,  false, true,  // '8', '9', ':', ---, ---, '=', ---, '?'
            false, true,  true,  true,  true,  true,  true,  true,  // ---, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
            true,  true,  true,  true,  true,  true,  true,  true,  // 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O'
            true,  true,  true,  true,  true,  true,  true,  true,  // 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'
            true,  true,  true,  false, false, false, false, false, // 'X', 'Y', 'Z', ---, ---, ---, ---, ---
            false, true,  true,  true,  true,  true,  true,  true,  // ---, 'a', 'b', 'c', 'd', 'e', 'f', 'g'
            true,  true,  true,  true,  true,  true,  true,  true,  // 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'
            true,  true,  true,  true,  true,  true,  true,  true,  // 'p', 'q', 'r', 's', 't', 'u', 'v', 'w'
            true,  true,  true,  false, false, false, false, false // 'x', 'y', 'z', ---, ---, ---, ---, ---
    };

    public static final char[] TO_LOWER_CASE =
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            ' ',  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, '\'',
            '(',  ')',  0x2A, '+',  ',',  '-',  '.',  '/',
            '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
            '8',  '9',  ':',  0x3B, 0x3C, '=',  0x3E, '?',
            0x40, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
            'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
            'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
            'x',  'y',  'z',  0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
            'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
            'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
            'x',  'y',  'z',  0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
            0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
            0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
            0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
            0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
            0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
            0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
            0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
    };

    public static final byte[] TO_LOWER_CASE_BYTE =
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            ' ',  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, '\'',
            '(',  ')',  0x2A, '+',  ',',  '-',  '.',  '/',
            '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
            '8',  '9',  ':',  0x3B, 0x3C, '=',  0x3E, '?',
            0x40, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
            'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
            'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
            'x',  'y',  'z',  0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
            'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
            'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
            'x',  'y',  'z',  0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
            ( byte ) 0x80, ( byte ) 0x81, ( byte ) 0x82, ( byte ) 0x83,
            ( byte ) 0x84, ( byte ) 0x85, ( byte ) 0x86, ( byte ) 0x87,
            ( byte ) 0x88, ( byte ) 0x89, ( byte ) 0x8A, ( byte ) 0x8B,
            ( byte ) 0x8C, ( byte ) 0x8D, ( byte ) 0x8E, ( byte ) 0x8F,
            ( byte ) 0x90, ( byte ) 0x91, ( byte ) 0x92, ( byte ) 0x93,
            ( byte ) 0x94, ( byte ) 0x95, ( byte ) 0x96, ( byte ) 0x97,
            ( byte ) 0x98, ( byte ) 0x99, ( byte ) 0x9A, ( byte ) 0x9B,
            ( byte ) 0x9C, ( byte ) 0x9D, ( byte ) 0x9E, ( byte ) 0x9F,
            ( byte ) 0xA0, ( byte ) 0xA1, ( byte ) 0xA2, ( byte ) 0xA3,
            ( byte ) 0xA4, ( byte ) 0xA5, ( byte ) 0xA6, ( byte ) 0xA7,
            ( byte ) 0xA8, ( byte ) 0xA9, ( byte ) 0xAA, ( byte ) 0xAB,
            ( byte ) 0xAC, ( byte ) 0xAD, ( byte ) 0xAE, ( byte ) 0xAF,
            ( byte ) 0xB0, ( byte ) 0xB1, ( byte ) 0xB2, ( byte ) 0xB3,
            ( byte ) 0xB4, ( byte ) 0xB5, ( byte ) 0xB6, ( byte ) 0xB7,
            ( byte ) 0xB8, ( byte ) 0xB9, ( byte ) 0xBA, ( byte ) 0xBB,
            ( byte ) 0xBC, ( byte ) 0xBD, ( byte ) 0xBE, ( byte ) 0xBF,
            ( byte ) 0xC0, ( byte ) 0xC1, ( byte ) 0xC2, ( byte ) 0xC3,
            ( byte ) 0xC4, ( byte ) 0xC5, ( byte ) 0xC6, ( byte ) 0xC7,
            ( byte ) 0xC8, ( byte ) 0xC9, ( byte ) 0xCA, ( byte ) 0xCB,
            ( byte ) 0xCC, ( byte ) 0xCD, ( byte ) 0xCE, ( byte ) 0xCF,
            ( byte ) 0xD0, ( byte ) 0xD1, ( byte ) 0xD2, ( byte ) 0xD3,
            ( byte ) 0xD4, ( byte ) 0xD5, ( byte ) 0xD6, ( byte ) 0xD7,
            ( byte ) 0xD8, ( byte ) 0xD9, ( byte ) 0xDA, ( byte ) 0xDB,
            ( byte ) 0xDC, ( byte ) 0xDD, ( byte ) 0xDE, ( byte ) 0xDF,
            ( byte ) 0xE0, ( byte ) 0xE1, ( byte ) 0xE2, ( byte ) 0xE3,
            ( byte ) 0xE4, ( byte ) 0xE5, ( byte ) 0xE6, ( byte ) 0xE7,
            ( byte ) 0xE8, ( byte ) 0xE9, ( byte ) 0xEA, ( byte ) 0xEB,
            ( byte ) 0xEC, ( byte ) 0xED, ( byte ) 0xEE, ( byte ) 0xEF,
            ( byte ) 0xF0, ( byte ) 0xF1, ( byte ) 0xF2, ( byte ) 0xF3,
            ( byte ) 0xF4, ( byte ) 0xF5, ( byte ) 0xF6, ( byte ) 0xF7,
            ( byte ) 0xF8, ( byte ) 0xF9, ( byte ) 0xFA, ( byte ) 0xFB,
            ( byte ) 0xFC, ( byte ) 0xFD, ( byte ) 0xFE,( byte ) 0xFF,
    };

    /** upperCase = 'A' .. 'Z', '0'..'9', '-' */
    public static final char[] UPPER_CASE =
        {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, '-', 0, 0,
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 0, 0, 0, 0, 0, 0,
            0, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
            'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
            'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
            'X', 'Y', 'Z', 0, 0, 0, 0, 0,
            0, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
            'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
            'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
            'X', 'Y', 'Z', 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
    };

    /** A empty byte array */
    public static final byte[] EMPTY_BYTES = new byte[0];


    /**
     * Private constructor
     */
    private Strings()
    {
    }


    /**
     * Helper function that dump an array of bytes in hex form
     *
     * @param buffer The bytes array to dump
     * @return A string representation of the array of bytes
     */
    public static String dumpBytes( byte[] buffer )
    {
        if ( buffer == null )
        {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        for ( int i = 0; i < buffer.length; i++ )
        {
            sb.append( "0x" ).append( ( char ) ( HEX_CHAR[( buffer[i] & 0x00F0 ) >> 4] ) ).append(
                ( char ) ( HEX_CHAR[buffer[i] & 0x000F] ) ).append( " " );
        }

        return sb.toString();
    }


    /**
     * Helper function that dump a byte in hex form
     *
     * @param octet The byte to dump
     * @return A string representation of the byte
     */
    public static String dumpByte( byte octet )
    {
        return new String( new byte[]
            { '0', 'x', HEX_CHAR[( octet & 0x00F0 ) >> 4], HEX_CHAR[octet & 0x000F] } );
    }


    /**
     * Helper function that returns a char from an hex
     *
     * @param hex The hex to dump
     * @return A char representation of the hex
     */
    public static char dumpHex( byte hex )
    {
        return ( char ) HEX_CHAR[hex & 0x000F];
    }


    /**
     * Helper function that dump an array of bytes in hex pair form,
     * without '0x' and space chars
     *
     * @param buffer The bytes array to dump
     * @return A string representation of the array of bytes
     */
    public static String dumpHexPairs( byte[] buffer )
    {
        if ( buffer == null )
        {
            return "";
        }

        char[] str = new char[buffer.length << 1];

        for ( int i = 0, pos = 0; i < buffer.length; i++ )
        {
            str[pos++] = ( char ) ( HEX_CHAR[( buffer[i] & 0x00F0 ) >> 4] );
            str[pos++] = ( char ) ( HEX_CHAR[buffer[i] & 0x000F] );
        }

        return new String( str );
    }


    /**
     * Put common code to deepTrim(String) and deepTrimToLower here.
     *
     * @param str the string to deep trim
     * @param toLowerCase how to normalize for case: upper or lower
     * @return the deep trimmed string
     * @see Strings#deepTrim( String )
     *
     * TODO Replace the toCharArray() by substring manipulations
     */
    public static String deepTrim( String str, boolean toLowerCase )
    {
        if ( ( null == str ) || ( str.length() == 0 ) )
        {
            return "";
        }

        char ch;
        char[] buf = str.toCharArray();
        char[] newbuf = new char[buf.length];
        boolean wsSeen = false;
        boolean isStart = true;
        int pos = 0;

        for ( int i = 0; i < str.length(); i++ )
        {
            ch = buf[i];

            // filter out all uppercase characters
            if ( toLowerCase && Character.isUpperCase( ch ) )
            {
                ch = Character.toLowerCase( ch );
            }

            // Check to see if we should add space
            if ( Character.isWhitespace( ch ) )
            {
                // If the buffer has had characters added already check last
                // added character. Only append a spc if last character was
                // not whitespace.
                if ( wsSeen )
                {
                    continue;
                }
                else
                {
                    wsSeen = true;

                    if ( isStart )
                    {
                        isStart = false;
                    }
                    else
                    {
                        newbuf[pos++] = ch;
                    }
                }
            }
            else
            {
                // Add all non-whitespace
                wsSeen = false;
                isStart = false;
                newbuf[pos++] = ch;
            }
        }

        return ( pos == 0 ? "" : new String( newbuf, 0, ( wsSeen ? pos - 1 : pos ) ) );
    }


    /**
     * This does the same thing as a trim but we also lowercase the string while
     * performing the deep trim within the same buffer. This saves us from
     * having to create multiple String and StringBuffer objects and is much
     * more efficient.
     *
     * @see Strings#deepTrim( String )
     */
    public static String deepTrimToLower( String string )
    {
        return deepTrim( string, true );
    }


    /**
     * A deep trim of a string remove whitespace from the ends as well as
     * excessive whitespace within the inside of the string between
     * non-whitespace characters. A deep trim reduces internal whitespace down
     * to a single space to preserve the whitespace separated tokenization order
     * of the String.
     *
     * @param string the string to deep trim.
     * @return the trimmed string.
     */
    public static String deepTrim( String string )
    {
        return deepTrim( string, false );
    }


    /**
     * Trims several consecutive characters into one.
     *
     * @param str the string to trim consecutive characters of
     * @param ch the character to trim down
     * @return the newly trimmed down string
     */
    public static String trimConsecutiveToOne( String str, char ch )
    {
        if ( ( null == str ) || ( str.length() == 0 ) )
        {
            return "";
        }

        char[] buffer = str.toCharArray();
        char[] newbuf = new char[buffer.length];
        int pos = 0;
        boolean same = false;

        for ( int i = 0; i < buffer.length; i++ )
        {
            char car = buffer[i];

            if ( car == ch )
            {
                if ( same )
                {
                    continue;
                }
                else
                {
                    same = true;
                    newbuf[pos++] = car;
                }
            }
            else
            {
                same = false;
                newbuf[pos++] = car;
            }
        }

        return new String( newbuf, 0, pos );
    }


    /**
     * Truncates large Strings showing a portion of the String's head and tail
     * with the center cut out and replaced with '...'. Also displays the total
     * length of the truncated string so size of '...' can be interpreted.
     * Useful for large strings in UIs or hex dumps to log files.
     *
     * @param str the string to truncate
     * @param head the amount of the head to display
     * @param tail the amount of the tail to display
     * @return the center truncated string
     */
    public static String centerTrunc( String str, int head, int tail )
    {
        StringBuffer buf = null;

        // Return as-is if String is smaller than or equal to the head plus the
        // tail plus the number of characters added to the trunc representation
        // plus the number of digits in the string length.
        if ( str.length() <= ( head + tail + 7 + str.length() / 10 ) )
        {
            return str;
        }

        buf = new StringBuffer();
        buf.append( '[' ).append( str.length() ).append( "][" );
        buf.append( str.substring( 0, head ) ).append( "..." );
        buf.append( str.substring( str.length() - tail ) );
        buf.append( ']' );
        return buf.toString();
    }


    /**
     * Gets a hex string from byte array.
     *
     * @param res the byte array
     * @return the hex string representing the binary values in the array
     */
    public static String toHexString( byte[] res )
    {
        StringBuffer buf = new StringBuffer( res.length << 1 );

        for ( int ii = 0; ii < res.length; ii++ )
        {
            String digit = Integer.toHexString( 0xFF & res[ii] );

            if ( digit.length() == 1 )
            {
                digit = '0' + digit;
            }

            buf.append( digit );
        }

        return buf.toString().toUpperCase();
    }


    /**
     * Get byte array from hex string
     *
     * @param hexString the hex string to convert to a byte array
     * @return the byte form of the hex string.
     */
    public static byte[] toByteArray( String hexString )
    {
        int arrLength = hexString.length() >> 1;
        byte[] buf = new byte[arrLength];

        for ( int ii = 0; ii < arrLength; ii++ )
        {
            int index = ii << 1;

            String digit = hexString.substring( index, index + 2 );
            buf[ii] = ( byte ) Integer.parseInt( digit, 16 );
        }

        return buf;
    }


    /**
     * This method is used to insert HTML block dynamically
     *
     * @param source the HTML code to be processes
     * @param replaceNl if true '\n' will be replaced by &lt;br>
     * @param replaceTag if true '<' will be replaced by &lt; and '>' will be replaced
     *            by &gt;
     * @param replaceQuote if true '\"' will be replaced by &quot;
     * @return the formated html block
     */
    public static String formatHtml( String source, boolean replaceNl, boolean replaceTag,
        boolean replaceQuote )
    {
        StringBuffer buf = new StringBuffer();
        int len = source.length();

        for ( int ii = 0; ii < len; ii++ )
        {
            char ch = source.charAt( ii );

            switch ( ch )
            {
                case '\"':
                    if ( replaceQuote )
                    {
                        buf.append( "&quot;" );
                    }
                    else
                    {
                        buf.append( ch );
                    }
                    break;

                case '<':
                    if ( replaceTag )
                    {
                        buf.append( "&lt;" );
                    }
                    else
                    {
                        buf.append( ch );
                    }
                    break;

                case '>':
                    if ( replaceTag )
                    {
                        buf.append( "&gt;" );
                    }
                    else
                    {
                        buf.append( ch );
                    }
                    break;

                case '\n':
                    if ( replaceNl )
                    {
                        if ( replaceTag )
                        {
                            buf.append( "&lt;br&gt;" );
                        }
                        else
                        {
                            buf.append( "<br>" );
                        }
                    }
                    else
                    {
                        buf.append( ch );
                    }
                    break;

                case '\r':
                    break;

                case '&':
                    buf.append( "&amp;" );
                    break;

                default:
                    buf.append( ch );
                    break;
            }
        }

        return buf.toString();
    }


    /**
     * Check if a text is present at the current position in another string.
     *
     * @param string The string which contains the data
     * @param index Current position in the string
     * @param text The text we want to check
     * @return <code>true</code> if the string contains the text.
     */
    public static boolean areEquals( String string, int index, String text )
    {
        if ( ( string == null ) || ( text == null ) )
        {
            return false;
        }

        int length1 = string.length();
        int length2 = text.length();

        if ( ( length1 == 0 ) || ( length1 <= index ) || ( index < 0 )
            || ( length2 == 0 ) || ( length2 > ( length1 + index ) ) )
        {
            return false;
        }
        else
        {
            return string.substring( index ).startsWith( text );
        }
    }


    /**
     * Test if the current character is equal to a specific character. This
     * function works only for character between 0 and 127, as it does compare a
     * byte and a char (which is 16 bits wide)
     *
     * @param byteArray The buffer which contains the data
     * @param index Current position in the buffer
     * @param car The character we want to compare with the current buffer position
     * @return <code>true</code> if the current character equals the given character.
     */
    public static boolean isCharASCII( byte[] byteArray, int index, char car )
    {
        if ( ( byteArray == null ) || ( byteArray.length == 0 ) || ( index < 0 ) || ( index >= byteArray.length ) )
        {
            return false;
        }
        else
        {
            return ( ( byteArray[index] == car ) ? true : false );
        }
    }


    /**
     * Test if the current character is equal to a specific character.
     *
     * @param string The String which contains the data
     * @param index Current position in the string
     * @param car The character we want to compare with the current string position
     * @return <code>true</code> if the current character equals the given character.
     */
    public static boolean isCharASCII( String string, int index, char car )
    {
        if ( string == null )
        {
            return false;
        }

        int length = string.length();

        if ( ( length == 0 ) || ( index < 0 ) || ( index >= length ) )
        {
            return false;
        }
        else
        {
            return string.charAt( index ) == car;
        }
    }

    private static final byte[] UTF8 = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
            0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
            0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F };


    /**
     * Return an UTF-8 encoded String
     *
     * @param bytes The byte array to be transformed to a String
     * @return A String.
     */
    public static String utf8ToString( byte[] bytes )
    {
        if ( bytes == null )
        {
            return "";
        }

        char[] chars = new char[bytes.length];
        int pos = 0;

        try
        {
            for ( byte b : bytes )
            {
                chars[pos++] = ( char ) UTF8[b];
            }
        }
        catch ( ArrayIndexOutOfBoundsException aioobe )
        {
            try
            {
                return new String( bytes, "UTF-8" );
            }
            catch ( UnsupportedEncodingException uee )
            {
                // if this happens something is really strange
                throw new RuntimeException( uee );
            }
        }

        return new String( chars );
    }


    /**
     * Return an UTF-8 encoded String
     *
     * @param bytes The byte array to be transformed to a String
     * @param length The length of the byte array to be converted
     * @return A String.
     */
    public static String utf8ToString( byte[] bytes, int length )
    {
        if ( bytes == null )
        {
            return "";
        }

        try
        {
            return new String( bytes, 0, length, "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * Return an UTF-8 encoded String
     *
     * @param bytes  The byte array to be transformed to a String
     * @param start the starting position in the byte array
     * @param length The length of the byte array to be converted
     * @return A String.
     */
    public static String utf8ToString( byte[] bytes, int start, int length )
    {
        if ( bytes == null )
        {
            return "";
        }

        try
        {
            return new String( bytes, start, length, "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * Check if a text is present at the current position in a buffer.
     *
     * @param bytes The buffer which contains the data
     * @param index Current position in the buffer
     * @param text The text we want to check
     * @return <code>true</code> if the buffer contains the text.
     */
    public static int areEquals( byte[] bytes, int index, String text )
    {
        if ( ( bytes == null ) || ( bytes.length == 0 ) || ( bytes.length <= index ) || ( index < 0 )
            || ( text == null ) )
        {
            return StringConstants.NOT_EQUAL;
        }
        else
        {
            try
            {
                byte[] data = text.getBytes( "UTF-8" );

                return areEquals( bytes, index, data );
            }
            catch ( UnsupportedEncodingException uee )
            {
                // if this happens something is really strange
                throw new RuntimeException( uee );
            }
        }
    }


    /**
     * Check if a text is present at the current position in a buffer.
     *
     * @param chars The buffer which contains the data
     * @param index Current position in the buffer
     * @param text The text we want to check
     * @return <code>true</code> if the buffer contains the text.
     */
    public static int areEquals( char[] chars, int index, String text )
    {
        return areEquals( chars, index, text, true );
    }


    /**
     * Check if a text is present at the current position in a buffer.
     *
     * @param chars The buffer which contains the data
     * @param index Current position in the buffer
     * @param text The text we want to check
     * @param caseSensitive If the comparison is case-sensitive
     * @return <code>true</code> if the buffer contains the text.
     */
    public static int areEquals( char[] chars, int index, String text, boolean caseSensitive )
    {
        if ( ( chars == null ) || ( chars.length == 0 ) || ( chars.length <= index ) || ( index < 0 )
            || ( text == null ) )
        {
            return StringConstants.NOT_EQUAL;
        }
        else
        {
            char[] data = text.toCharArray();

            return areEquals( chars, index, data, caseSensitive );
        }
    }


    /**
     * Check if a text is present at the current position in a buffer.
     *
     * @param chars The buffer which contains the data
     * @param index Current position in the buffer
     * @param chars2 The text we want to check
     * @return <code>true</code> if the buffer contains the text.
     */
    public static int areEquals( char[] chars, int index, char[] chars2 )
    {
        return areEquals( chars, index, chars2, true );
    }


    /**
     * Check if a text is present at the current position in a buffer.
     *
     * @param chars The buffer which contains the data
     * @param index Current position in the buffer
     * @param chars2 The text we want to check
     * @param caseSensitive If the comparison is case-sensitive
     * @return <code>true</code> if the buffer contains the text.
     */
    public static int areEquals( char[] chars, int index, char[] chars2, boolean caseSensitive )
    {
        if ( ( chars == null ) || ( chars.length == 0 ) || ( chars.length <= index ) || ( index < 0 )
            || ( chars2 == null ) || ( chars2.length == 0 )
            || ( chars2.length > ( chars.length - index ) ) )
        {
            return StringConstants.NOT_EQUAL;
        }
        else
        {
            for ( int i = 0; i < chars2.length; i++ )
            {
                char c1 = chars[index++];
                char c2 = chars2[i];

                if ( !caseSensitive )
                {
                    c1 = Character.toLowerCase( c1 );
                    c2 = Character.toLowerCase( c2 );
                }

                if ( c1 != c2 )
                {
                    return StringConstants.NOT_EQUAL;
                }
            }

            return index;
        }
    }


    /**
     * Check if a text is present at the current position in a buffer.
     *
     * @param bytes The buffer which contains the data
     * @param index Current position in the buffer
     * @param bytes2 The text we want to check
     * @return <code>true</code> if the buffer contains the text.
     */
    public static int areEquals( byte[] bytes, int index, byte[] bytes2 )
    {
        if ( ( bytes == null ) || ( bytes.length == 0 ) || ( bytes.length <= index ) || ( index < 0 )
            || ( bytes2 == null ) || ( bytes2.length == 0 )
            || ( bytes2.length > ( bytes.length - index ) ) )
        {
            return StringConstants.NOT_EQUAL;
        }
        else
        {
            for ( int i = 0; i < bytes2.length; i++ )
            {
                if ( bytes[index++] != bytes2[i] )
                {
                    return StringConstants.NOT_EQUAL;
                }
            }

            return index;
        }
    }


    /**
     * <p>
     * Checks if a String is empty ("") or null.
     * </p>
     *
     * <pre>
     *  StringUtils.isEmpty(null)      = true
     *  StringUtils.isEmpty(&quot;&quot;)        = true
     *  StringUtils.isEmpty(&quot; &quot;)       = false
     *  StringUtils.isEmpty(&quot;bob&quot;)     = false
     *  StringUtils.isEmpty(&quot;  bob  &quot;) = false
     * </pre>
     *
     * <p>
     * NOTE: This method changed in Lang version 2.0. It no longer trims the
     * String. That functionality is available in isBlank().
     * </p>
     *
     * @param str the String to check, may be null
     * @return <code>true</code> if the String is empty or null
     */
    public static boolean isEmpty( String str )
    {
        return ( str == null ) || ( str.length() == 0 );
    }


    /**
     * Checks if a bytes array is empty or null.
     *
     * @param bytes The bytes array to check, may be null
     * @return <code>true</code> if the bytes array is empty or null
     */
    public static boolean isEmpty( byte[] bytes )
    {
        return ( bytes == null ) || ( bytes.length == 0 );
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from both start and ends of this String,
     * handling <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start and end characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trim(null)          = null
     *  StringUtils.trim(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trim(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trim(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trim(&quot;    abc    &quot;) = &quot;abc&quot;
     * </pre>
     *
     * @param str the String to be trimmed, may be null
     * @return the trimmed string, <code>null</code> if null String input
     */
    public static String trim( String str )
    {
        return ( isEmpty( str ) ? "" : str.trim() );
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from both start and ends of this bytes
     * array, handling <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start and end characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trim(null)          = null
     *  StringUtils.trim(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trim(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trim(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trim(&quot;    abc    &quot;) = &quot;abc&quot;
     * </pre>
     *
     * @param bytes the byte array to be trimmed, may be null
     *
     * @return the trimmed byte array
     */
    public static byte[] trim( byte[] bytes )
    {
        if ( isEmpty( bytes ) )
        {
            return StringConstants.EMPTY_BYTES;
        }

        int start = trimLeft( bytes, 0 );
        int end = trimRight( bytes, bytes.length - 1 );

        int length = end - start + 1;

        if ( length != 0 )
        {
            byte[] newBytes = new byte[end - start + 1];

            System.arraycopy( bytes, start, newBytes, 0, length );

            return newBytes;
        }
        else
        {
            return StringConstants.EMPTY_BYTES;
        }
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from start of this String, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimLeft(null)          = null
     *  StringUtils.trimLeft(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimLeft(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimLeft(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimLeft(&quot;    abc    &quot;) = &quot;abc    &quot;
     * </pre>
     *
     * @param str the String to be trimmed, may be null
     * @return the trimmed string, <code>null</code> if null String input
     */
    public static String trimLeft( String str )
    {
        if ( isEmpty( str ) )
        {
            return "";
        }

        int start = 0;
        int end = str.length();

        while ( ( start < end ) && ( str.charAt( start ) == ' ' ) )
        {
            start++;
        }

        return ( start == 0 ? str : str.substring( start ) );
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from start of this array, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimLeft(null)          = null
     *  StringUtils.trimLeft(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimLeft(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimLeft(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimLeft(&quot;    abc    &quot;) = &quot;abc    &quot;
     * </pre>
     *
     * @param chars the chars array to be trimmed, may be null
     * @return the position of the first char which is not a space, or the last
     *         position of the array.
     */
    public static int trimLeft( char[] chars, int pos )
    {
        if ( chars == null )
        {
            return pos;
        }

        while ( ( pos < chars.length ) && ( chars[pos] == ' ' ) )
        {
            pos++;
        }

        return pos;
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from a position in this array, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimLeft(null)          = null
     *  StringUtils.trimLeft(&quot;&quot;,...)            = &quot;&quot;
     *  StringUtils.trimLeft(&quot;     &quot;,...)       = &quot;&quot;
     *  StringUtils.trimLeft(&quot;abc&quot;,...)         = &quot;abc&quot;
     *  StringUtils.trimLeft(&quot;    abc    &quot;,...) = &quot;abc    &quot;
     * </pre>
     *
     * @param string the string to be trimmed, may be null
     * @param pos The starting position
     */
    public static void trimLeft( String string, Position pos )
    {
        if ( string == null )
        {
            return;
        }

        int length = string.length();

        while ( ( pos.start < length ) && ( string.charAt( pos.start ) == ' ' ) )
        {
            pos.start++;
        }

        pos.end = pos.start;
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from a position in this array, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimLeft(null)          = null
     *  StringUtils.trimLeft(&quot;&quot;,...)            = &quot;&quot;
     *  StringUtils.trimLeft(&quot;     &quot;,...)       = &quot;&quot;
     *  StringUtils.trimLeft(&quot;abc&quot;,...)         = &quot;abc&quot;
     *  StringUtils.trimLeft(&quot;    abc    &quot;,...) = &quot;abc    &quot;
     * </pre>
     *
     * @param bytes the byte array to be trimmed, may be null
     * @param pos The starting position
     */
    public static void trimLeft( byte[] bytes, Position pos )
    {
        if ( bytes == null )
        {
            return;
        }

        int length = bytes.length;

        while ( ( pos.start < length ) && ( bytes[pos.start] == ' ' ) )
        {
            pos.start++;
        }

        pos.end = pos.start;
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from start of this array, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimLeft(null)          = null
     *  StringUtils.trimLeft(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimLeft(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimLeft(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimLeft(&quot;    abc    &quot;) = &quot;abc    &quot;
     * </pre>
     *
     * @param bytes the byte array to be trimmed, may be null
     * @return the position of the first byte which is not a space, or the last
     *         position of the array.
     */
    public static int trimLeft( byte[] bytes, int pos )
    {
        if ( bytes == null )
        {
            return pos;
        }

        while ( ( pos < bytes.length ) && ( bytes[pos] == ' ' ) )
        {
            pos++;
        }

        return pos;
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from end of this String, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimRight(null)          = null
     *  StringUtils.trimRight(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimRight(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimRight(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimRight(&quot;    abc    &quot;) = &quot;    abc&quot;
     * </pre>
     *
     * @param str the String to be trimmed, may be null
     * @return the trimmed string, <code>null</code> if null String input
     */
    public static String trimRight( String str )
    {
        if ( isEmpty( str ) )
        {
            return "";
        }

        int length = str.length();
        int end = length;

        while ( ( end > 0 ) && ( str.charAt( end - 1 ) == ' ' ) )
        {
            if ( ( end > 1 ) && ( str.charAt( end - 2 ) == '\\' ) )
            {
                break;
            }

            end--;
        }

        return ( end == length ? str : str.substring( 0, end ) );
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from end of this String, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimRight(null)          = null
     *  StringUtils.trimRight(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimRight(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimRight(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimRight(&quot;    abc    &quot;) = &quot;    abc&quot;
     * </pre>
     *
     * @param str the String to be trimmed, may be null
     * @param escapedSpace The last escaped space, if any
     * @return the trimmed string, <code>null</code> if null String input
     */
    public static String trimRight( String str, int escapedSpace )
    {
        if ( isEmpty( str ) )
        {
            return "";
        }

        int length = str.length();
        int end = length;

        while ( ( end > 0 ) && ( str.charAt( end - 1 ) == ' ' ) && ( end > escapedSpace ) )
        {
            if ( ( end > 1 ) && ( str.charAt( end - 2 ) == '\\' ) )
            {
                break;
            }

            end--;
        }

        return ( end == length ? str : str.substring( 0, end ) );
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from end of this array, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimRight(null)          = null
     *  StringUtils.trimRight(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimRight(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimRight(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimRight(&quot;    abc    &quot;) = &quot;    abc&quot;
     * </pre>
     *
     * @param chars the chars array to be trimmed, may be null
     * @return the position of the first char which is not a space, or the last
     *         position of the array.
     */
    public static int trimRight( char[] chars, int pos )
    {
        if ( chars == null )
        {
            return pos;
        }

        while ( ( pos >= 0 ) && ( chars[pos - 1] == ' ' ) )
        {
            pos--;
        }

        return pos;
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from end of this string, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimRight(null)          = null
     *  StringUtils.trimRight(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimRight(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimRight(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimRight(&quot;    abc    &quot;) = &quot;    abc&quot;
     * </pre>
     *
     * @param string the string to be trimmed, may be null
     * @return the position of the first char which is not a space, or the last
     *         position of the string.
     */
    public static String trimRight( String string, Position pos )
    {
        if ( string == null )
        {
            return "";
        }

        while ( ( pos.end >= 0 ) && ( string.charAt( pos.end - 1 ) == ' ' ) )
        {
            if ( ( pos.end > 1 ) && ( string.charAt( pos.end - 2 ) == '\\' ) )
            {
                break;
            }

            pos.end--;
        }

        return ( pos.end == string.length() ? string : string.substring( 0, pos.end ) );
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from end of this string, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimRight(null)          = null
     *  StringUtils.trimRight(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimRight(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimRight(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimRight(&quot;    abc    &quot;) = &quot;    abc&quot;
     * </pre>
     *
     * @param bytes the byte array to be trimmed, may be null
     * @return the position of the first char which is not a space, or the last
     *         position of the byte array.
     */
    public static String trimRight( byte[] bytes, Position pos )
    {
        if ( bytes == null )
        {
            return "";
        }

        while ( ( pos.end >= 0 ) && ( bytes[pos.end - 1] == ' ' ) )
        {
            if ( ( pos.end > 1 ) && ( bytes[pos.end - 2] == '\\' ) )
            {
                break;
            }

            pos.end--;
        }

        if ( pos.end == bytes.length )
        {
            return utf8ToString( bytes );
        }
        else
        {
            return utf8ToString( bytes, pos.end );
        }
    }


    /**
     * <p>
     * Removes spaces (char &lt;= 32) from end of this array, handling
     * <code>null</code> by returning <code>null</code>.
     * </p>
     * Trim removes start characters &lt;= 32.
     *
     * <pre>
     *  StringUtils.trimRight(null)          = null
     *  StringUtils.trimRight(&quot;&quot;)            = &quot;&quot;
     *  StringUtils.trimRight(&quot;     &quot;)       = &quot;&quot;
     *  StringUtils.trimRight(&quot;abc&quot;)         = &quot;abc&quot;
     *  StringUtils.trimRight(&quot;    abc    &quot;) = &quot;    abc&quot;
     * </pre>
     *
     * @param bytes the byte array to be trimmed, may be null
     * @return the position of the first char which is not a space, or the last
     *         position of the array.
     */
    public static int trimRight( byte[] bytes, int pos )
    {
        if ( bytes == null )
        {
            return pos;
        }

        while ( ( pos >= 0 ) && ( bytes[pos] == ' ' ) )
        {
            pos--;
        }

        return pos;
    }


    /**
     * Get the character at a given position in a string, checking for limits
     *
     * @param string The string which contains the data
     * @param index Current position in the string
     * @return The character at the given position, or '\0' if something went wrong
     */
    public static char charAt( String string, int index )
    {
        if ( string == null )
        {
            return '\0';
        }

        int length = string.length();

        if ( ( length == 0 ) || ( index < 0 ) || ( index >= length ) )
        {
            return '\0';
        }
        else
        {
            return string.charAt( index );
        }
    }


    /**
     * Get the byte at a given position in a byte array, checking for limits
     *
     * @param bytes The byte[] which contains the data
     * @param index Current position in the byte[]
     * @return The byte at the given position, or '\0' if something went wrong
     */
    public static byte byteAt( byte[] bytes, int index )
    {
        if ( bytes == null )
        {
            return '\0';
        }

        int length = bytes.length;

        if ( ( length == 0 ) || ( index < 0 ) || ( index >= length ) )
        {
            return '\0';
        }
        else
        {
            return bytes[index];
        }
    }


    /**
     * Get the char at a given position in a byte array, checking for limits
     *
     * @param chars The char[] which contains the data
     * @param index Current position in the char[]
     * @return The byte at the given position, or '\0' if something went wrong
     */
    public static char charAt( char[] chars, int index )
    {
        if ( chars == null )
        {
            return '\0';
        }

        int length = chars.length;

        if ( ( length == 0 ) || ( index < 0 ) || ( index >= length ) )
        {
            return '\0';
        }
        else
        {
            return chars[index];
        }
    }


    /**
     * Transform an array of ASCII bytes to a string. the byte array should contains
     * only values in [0, 127].
     *
     * @param bytes The byte array to transform
     * @return The resulting string
     */
    public static String asciiBytesToString( byte[] bytes )
    {
        if ( ( bytes == null ) || ( bytes.length == 0 ) )
        {
            return "";
        }

        char[] result = new char[bytes.length];

        for ( int i = 0; i < bytes.length; i++ )
        {
            result[i] = ( char ) bytes[i];
        }

        return new String( result );
    }


    /**
     * Return UTF-8 encoded byte[] representation of a String
     *
     * @param string The string to be transformed to a byte array
     * @return The transformed byte array
     */
    public static byte[] getBytesUtf8( String string )
    {
        if ( string == null )
        {
            return EMPTY_BYTES;
        }

        try
        {
            return string.getBytes( "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * When the string to convert to bytes is pure ascii, this is a faster 
     * method than the getBytesUtf8. Otherwise, it's slower.
     * 
     * @param string The string to convert to byte[]
     * @return The bytes 
     */
    public static byte[] getBytesUtf8Ascii( String string )
    {
        if ( string == null )
        {
            return new byte[0];
        }

        try
        {
            try
            {
                char[] chars = string.toCharArray();
                byte[] bytes = new byte[chars.length];
                int pos = 0;

                for ( char c : chars )
                {
                    bytes[pos++] = UTF8[c];
                }

                return bytes;
            }
            catch ( ArrayIndexOutOfBoundsException aioobe )
            {
                return string.getBytes( "UTF-8" );
            }
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * Get the default charset
     *
     * @return The default charset
     */
    public static String getDefaultCharsetName()
    {
        if ( null == defaultCharset )
        {
            try
            {
                // Try with jdk 1.5 method, if we are using a 1.5 jdk :)
                Method method = Charset.class.getMethod( "defaultCharset", new Class[0] );
                defaultCharset = ( ( Charset ) method.invoke( null, new Object[0] ) ).name();
            }
            catch ( NoSuchMethodException e )
            {
                // fall back to old method
                defaultCharset = new OutputStreamWriter( new ByteArrayOutputStream() ).getEncoding();
            }
            catch ( InvocationTargetException e )
            {
                // fall back to old method
                defaultCharset = new OutputStreamWriter( new ByteArrayOutputStream() ).getEncoding();
            }
            catch ( IllegalAccessException e )
            {
                // fall back to old method
                defaultCharset = new OutputStreamWriter( new ByteArrayOutputStream() ).getEncoding();
            }
        }

        return defaultCharset;
    }


    /**
     * <p>
     * Compares two Strings, returning <code>true</code> if they are equal.
     * </p>
     * <p>
     * <code>null</code>s are handled without exceptions. Two
     * <code>null</code> references are considered to be equal. The comparison
     * is case sensitive.
     * </p>
     *
     * <pre>
     *  StringUtils.equals(null, null)   = true
     *  StringUtils.equals(null, &quot;abc&quot;)  = false
     *  StringUtils.equals(&quot;abc&quot;, null)  = false
     *  StringUtils.equals(&quot;abc&quot;, &quot;abc&quot;) = true
     *  StringUtils.equals(&quot;abc&quot;, &quot;ABC&quot;) = false
     * </pre>
     *
     * @see String#equals(Object)
     * @param str1 the first String, may be null
     * @param str2 the second String, may be null
     * @return <code>true</code> if the Strings are equal, case sensitive, or
     *         both <code>null</code>
     */
    public static boolean equals( String str1, String str2 )
    {
        return str1 == null ? str2 == null : str1.equals( str2 );
    }


    /**
     * Utility method that return a String representation of a list
     *
     * @param list The list to transform to a string
     * @return A csv string
     */
    public static String listToString( List<?> list )
    {
        if ( ( list == null ) || ( list.size() == 0 ) )
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;

        for ( Object elem : list )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            sb.append( elem );
        }

        return sb.toString();
    }


    /**
     * Utility method that return a String representation of a set
     *
     * @param set The set to transform to a string
     * @return A csv string
     */
    public static String setToString( Set<?> set )
    {
        if ( ( set == null ) || ( set.size() == 0 ) )
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;

        for ( Object elem : set )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            sb.append( elem );
        }

        return sb.toString();
    }


    /**
     * Utility method that return a String representation of a list
     *
     * @param list The list to transform to a string
     * @param tabs The tabs to add in front of the elements
     * @return A csv string
     */
    public static String listToString( List<?> list, String tabs )
    {
        if ( ( list == null ) || ( list.size() == 0 ) )
        {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        for ( Object elem : list )
        {
            sb.append( tabs );
            sb.append( elem );
            sb.append( '\n' );
        }

        return sb.toString();
    }


    /**
     * Utility method that return a String representation of a map. The elements
     * will be represented as "key = value"
     *
     * @param map The map to transform to a string
     * @return A csv string
     */
    public static String mapToString( Map<?, ?> map )
    {
        if ( ( map == null ) || ( map.size() == 0 ) )
        {
            return "";
        }

        StringBuffer sb = new StringBuffer();
        boolean isFirst = true;

        for ( Map.Entry<?, ?> entry : map.entrySet() )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            sb.append( entry.getKey() );
            sb.append( " = '" ).append( entry.getValue() ).append( "'" );
        }

        return sb.toString();
    }


    /**
     * Utility method that return a String representation of a map. The elements
     * will be represented as "key = value"
     *
     * @param map The map to transform to a string
     * @param tabs The tabs to add in ffront of the elements
     * @return A csv string
     */
    public static String mapToString( Map<?, ?> map, String tabs )
    {
        if ( ( map == null ) || ( map.size() == 0 ) )
        {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        for ( Map.Entry<?, ?> entry : map.entrySet() )
        {
            sb.append( tabs );
            sb.append( entry.getKey() );

            sb.append( " = '" ).append( entry.getValue().toString() ).append( "'\n" );
        }

        return sb.toString();
    }


    /**
     * Rewrote the toLowercase method to improve performances.
     * In Ldap, attributesType are supposed to use ASCII chars :
     * 'a'-'z', 'A'-'Z', '0'-'9', '.' and '-' only.
     *
     * @param value The String to lowercase
     * @return The lowercase string
     */
    public static String toLowerCase( String value )
    {
        if ( ( null == value ) || ( value.length() == 0 ) )
        {
            return "";
        }

        char[] chars = value.toCharArray();

        for ( int i = 0; i < chars.length; i++ )
        {
            chars[i] = TO_LOWER_CASE[chars[i]];
        }

        return new String( chars );
    }


    /**
     * Rewrote the toLowercase method to improve performances.
     * In Ldap, attributesType are supposed to use ASCII chars :
     * 'a'-'z', 'A'-'Z', '0'-'9', '.' and '-' only.
     *
     * @param value The byte[] to lowercase
     * @return The lowercase string
     */
    public static String toLowerCase( byte[] value )
    {
        if ( ( null == value ) || ( value.length == 0 ) )
        {
            return "";
        }

        for ( int i = 0; i < value.length; i++ )
        {
            value[i] = TO_LOWER_CASE_BYTE[value[i]];
        }

        return new String( value );
    }


    /**
     * Rewrote the toLowercase method to improve performances.
     * In Ldap, attributesType are supposed to use ASCII chars :
     * 'a'-'z', 'A'-'Z', '0'-'9', '.' and '-' only.
     *
     * @param value The String to uppercase
     * @return The uppercase string
     */
    public static String toUpperCase( String value )
    {
        if ( ( null == value ) || ( value.length() == 0 ) )
        {
            return "";
        }

        char[] chars = value.toCharArray();

        for ( int i = 0; i < chars.length; i++ )
        {
            chars[i] = UPPER_CASE[chars[i]];
        }

        return new String( chars );
    }


    /**
     * <p>
     * Converts a String to upper case as per {@link String#toUpperCase()}.
     * </p>
     * <p>
     * A <code>null</code> input String returns <code>null</code>.
     * </p>
     *
     * <pre>
     *  StringUtils.upperCase(null)  = null
     *  StringUtils.upperCase(&quot;&quot;)    = &quot;&quot;
     *  StringUtils.upperCase(&quot;aBc&quot;) = &quot;ABC&quot;
     * </pre>
     *
     * @param str the String to upper case, may be null
     * @return the upper cased String, <code>null</code> if null String input
     */
    public static String upperCase( String str )
    {
        if ( str == null )
        {
            return null;
        }

        return str.toUpperCase();
    }


    /**
     * <p>
     * Converts a String to lower case as per {@link String#toLowerCase()}.
     * </p>
     * <p>
     * A <code>null</code> input String returns <code>null</code>.
     * </p>
     *
     * <pre>
     *  StringUtils.lowerCase(null)  = null
     *  StringUtils.lowerCase(&quot;&quot;)    = &quot;&quot;
     *  StringUtils.lowerCase(&quot;aBc&quot;) = &quot;abc&quot;
     * </pre>
     *
     * @param str the String to lower case, may be null
     * @return the lower cased String, <code>null</code> if null String input
     */
    public static String lowerCase( String str )
    {
        if ( str == null )
        {
            return null;
        }

        return str.toLowerCase( Locale.ENGLISH );
    }


    /**
     * Rewrote the toLowercase method to improve performances.
     * In Ldap, attributesType are supposed to use ASCII chars :
     * 'a'-'z', 'A'-'Z', '0'-'9', '.' and '-' only. We will take
     * care of any other chars either.
     *
     * @param str The String to lowercase
     * @return The lowercase string
     */
    public static String lowerCaseAscii( String str )
    {
        if ( str == null )
        {
            return null;
        }

        char[] chars = str.toCharArray();
        int pos = 0;

        for ( char c : chars )
        {
            chars[pos++] = TO_LOWER_CASE[c];
        }

        return new String( chars );
    }


    /**
     *
     * Check that a String is a valid PrintableString. A PrintableString contains only
     * the following set of chars :
     * { ' ', ''', '(', ')', '+', '-', '.', '/', [0-9], ':', '=', '?', [A-Z], [a-z]}
     *
     * @param str The String to check
     * @return <code>true</code> if the string is a PrintableString or is empty,
     * <code>false</code> otherwise
     */
    public static boolean isPrintableString( String str )
    {
        if ( ( str == null ) || ( str.length() == 0 ) )
        {
            return true;
        }

        for ( char c : str.toCharArray() )
        {
            if ( ( c > 127 ) || !IS_PRINTABLE_CHAR[c] )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * <p>
     * Checks if a String is not empty ("") and not null.
     * </p>
     *
     * <pre>
     *  StringUtils.isNotEmpty(null)      = false
     *  StringUtils.isNotEmpty(&quot;&quot;)        = false
     *  StringUtils.isNotEmpty(&quot; &quot;)       = true
     *  StringUtils.isNotEmpty(&quot;bob&quot;)     = true
     *  StringUtils.isNotEmpty(&quot;  bob  &quot;) = true
     * </pre>
     *
     * @param str the String to check, may be null
     * @return <code>true</code> if the String is not empty and not null
     */
    public static boolean isNotEmpty( String str )
    {
        return ( str != null ) && ( str.length() > 0 );
    }


    /**
     *
     * Check that a String is a valid IA5String. An IA5String contains only
     * char which values is between [0, 7F]
     *
     * @param str The String to check
     * @return <code>true</code> if the string is an IA5String or is empty,
     * <code>false</code> otherwise
     */
    public static boolean isIA5String( String str )
    {
        if ( ( str == null ) || ( str.length() == 0 ) )
        {
            return true;
        }

        // All the chars must be in [0x00, 0x7F]
        for ( char c : str.toCharArray() )
        {
            if ( ( c < 0 ) || ( c > 0x7F ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * Checks to see if a String is a valid UUID.
     *
     * @param uuid the UUID to check for validity
     * @return true if the UUID is valid, false otherwise
     */
    public static boolean isValidUuid( String uuid )
    {
        byte[] b = uuid.getBytes();

        if ( b.length < 36 )
        {
            return false;
        }

        if ( isHex( b[0] ) && isHex( b[1] ) && isHex( b[2] ) && isHex( b[3] )
            && isHex( b[4] ) && isHex( b[5] ) && isHex( b[6] ) && isHex( b[7] )
            && ( b[8] == '-' )
            && isHex( b[9] ) && isHex( b[10] ) && isHex( b[11] ) && isHex( b[12] )
            && ( b[13] == '-' )
            && isHex( b[14] ) && isHex( b[15] ) && isHex( b[16] ) && isHex( b[17] )
            && ( b[18] == '-' )
            && isHex( b[19] ) && isHex( b[20] ) && isHex( b[21] ) && isHex( b[22] )
            && ( b[23] == '-' )
            && isHex( b[24] ) && isHex( b[25] ) && isHex( b[26] ) && isHex( b[27] )
            && isHex( b[28] ) && isHex( b[29] ) && isHex( b[30] ) && isHex( b[31] )
            && isHex( b[32] ) && isHex( b[33] ) && isHex( b[34] ) && isHex( b[35] ) )
        {
            // There is not that much more we can check.
            LOG.debug( "Syntax valid for '{}'", uuid );
            return true;
        }

        LOG.debug( "Syntax invalid for '{}'", uuid );
        return false;
    }


    /**
     * converts the bytes of a UUID to string
     *
     * @param bytes bytes of a UUID
     * @return UUID in string format
     */
    public static String uuidToString( byte[] bytes )
    {
        if ( ( bytes == null ) || ( bytes.length != 16 ) )
        {
            return "Invalid UUID";
        }

        char[] hex = encodeHex( bytes );
        StringBuffer sb = new StringBuffer();
        sb.append( hex, 0, 8 );
        sb.append( '-' );
        sb.append( hex, 8, 4 );
        sb.append( '-' );
        sb.append( hex, 12, 4 );
        sb.append( '-' );
        sb.append( hex, 16, 4 );
        sb.append( '-' );
        sb.append( hex, 20, 12 );

        return Strings.toLowerCase( sb.toString() );
    }


    /**
     * converts the string representation of an UUID to bytes
     *
     * @param string the string representation of an UUID
     * @return the bytes, null if the the syntax is not valid
     */
    public static byte[] uuidToBytes( String string )
    {
        if ( !isValidUuid( string ) )
        {
            return null;
        }

        char[] chars = string.toCharArray();
        byte[] bytes = new byte[16];
        bytes[0] = getHexValue( chars[0], chars[1] );
        bytes[1] = getHexValue( chars[2], chars[3] );
        bytes[2] = getHexValue( chars[4], chars[5] );
        bytes[3] = getHexValue( chars[6], chars[7] );

        bytes[4] = getHexValue( chars[9], chars[10] );
        bytes[5] = getHexValue( chars[11], chars[12] );

        bytes[6] = getHexValue( chars[14], chars[15] );
        bytes[7] = getHexValue( chars[16], chars[17] );

        bytes[8] = getHexValue( chars[19], chars[20] );
        bytes[9] = getHexValue( chars[21], chars[22] );

        bytes[10] = getHexValue( chars[24], chars[25] );
        bytes[11] = getHexValue( chars[26], chars[27] );
        bytes[12] = getHexValue( chars[28], chars[29] );
        bytes[13] = getHexValue( chars[30], chars[31] );
        bytes[14] = getHexValue( chars[32], chars[33] );
        bytes[15] = getHexValue( chars[34], chars[35] );

        return bytes;
    }


    /**
     * Copy a byte array into a new byte array
     *
     * @param value the byte array to copy
     * @return The copied byte array
     */
    public static byte[] copy( byte[] value )
    {
        if ( isEmpty( value ) )
        {
            return StringConstants.EMPTY_BYTES;
        }

        byte[] copy = new byte[value.length];
        System.arraycopy( value, 0, copy, 0, value.length );

        return copy;
    }


    /**
     * From commons-httpclients. Converts the byte array of HTTP content
     * characters to a string. If the specified charset is not supported,
     * default system encoding is used.
     *
     * @param data the byte array to be encoded
     * @param offset the index of the first byte to encode
     * @param length the number of bytes to encode
     * @param charset the desired character encoding
     * @return The result of the conversion.
     * @since 3.0
     */
    public static String getString( final byte[] data, int offset, int length, String charset )
    {
        if ( data == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04411 ) );
        }

        if ( ( charset == null ) || ( charset.length() == 0 ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04412 ) );
        }

        try
        {
            return new String( data, offset, length, charset );
        }
        catch ( UnsupportedEncodingException e )
        {
            return new String( data, offset, length );
        }
    }


    /**
     * From commons-httpclients. Converts the byte array of HTTP content
     * characters to a string. If the specified charset is not supported,
     * default system encoding is used.
     *
     * @param data the byte array to be encoded
     * @param charset the desired character encoding
     * @return The result of the conversion.
     * @since 3.0
     */
    public static String getString( final byte[] data, String charset )
    {
        return getString( data, 0, data.length, charset );
    }


    /**
     * Create a new UUID using a long as the least significant bits
     * 
     * @param value The least significant bits.
     * @return
     */
    public static String getUUID( long value )
    {
        return new UUID( 0, value ).toString();
    }
    
    
    /**
     * Past an ASCII String to a number
     *
     * @param value The string to parse
     * @return the parsed value.
     * @throws NumberFormatException If we don't have a number
     */
    public static int parseInt( String value ) throws NumberFormatException
    {
        long res = 0;
        
        for ( char c : value.toCharArray() )
        {
            if ( ( c >= '0' ) && ( c <= '9' ) )
            {
                res = res * 10 + ( c - '0' );
                
                if ( res > Integer.MAX_VALUE )
                {
                    throw new NumberFormatException( "Integer " + value + " is too big" );
                }
            }
            else
            {
                throw new NumberFormatException( "Integer " + value + " is not valid" );
            }
        }
        
        return (int)res;
    }
}
