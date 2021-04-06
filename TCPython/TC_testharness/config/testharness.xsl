<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="3.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xs="http://www.w3.org/2001/XMLSchema">
    <xsl:output omit-xml-declaration="yes" indent="yes"/>



<xsl:template name="linebreaklongwords">
<xsl:param name="str"/>
<xsl:param name="len"/>
<xsl:for-each select="$str">
<xsl:choose>
<xsl:when test="string-length(.) &gt; $len">
<xsl:call-template name="linebreaklongwordsub">
<xsl:with-param name="str" select="." />
<xsl:with-param name="len" select="$len" />



<xsl:with-param name="char"><xsl:text>&#8203;</xsl:text></xsl:with-param>
</xsl:call-template>
</xsl:when>
<xsl:otherwise>
<xsl:choose>
<xsl:when test="position()=last()">
<xsl:copy-of select="."/>
</xsl:when>
<xsl:otherwise>
<xsl:copy-of select="."/><xsl:text> </xsl:text>
</xsl:otherwise>
</xsl:choose>
</xsl:otherwise>
</xsl:choose>
</xsl:for-each>
</xsl:template>

<xsl:template name="linebreaklongwordsub">
<xsl:param name="str"/>
<xsl:param name="len"/>
<xsl:param name="char"/>
<xsl:choose>
<xsl:when test="string-length($str) &gt; $len">
<xsl:value-of select="substring($str,1,$len)"/>
<xsl:value-of select="$char"/>
<xsl:call-template name="linebreaklongwordsub">
<xsl:with-param name="str" select="substring($str,$len + 1)" />
<xsl:with-param name="len" select="$len" />
<xsl:with-param name="char" select="$char" />
</xsl:call-template>
</xsl:when>
<xsl:otherwise>
<xsl:value-of select="$str"/><xsl:text> </xsl:text>
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="/">
  <html>
  <body bgcolor="#9090CC" style="word-wrap:break-word;">
  <h2>TestHarness results</h2>
  <table border="1" style="border-collapse: collapse;">
  <xsl:for-each select="testharness/*">
  <tr>
  <xsl:if test="local-name()='message'">
  <xsl:choose>
        <xsl:when test="level='error'">
            <xsl:attribute name="bgcolor">#FF0000</xsl:attribute>
        </xsl:when>
        <xsl:when test="level='system'">
            <xsl:attribute name="bgcolor">#FFFF00</xsl:attribute>
        </xsl:when>
        <xsl:otherwise>
            <xsl:attribute name="bgcolor">#00CC00</xsl:attribute>
        </xsl:otherwise>
  </xsl:choose>
  </xsl:if>
    <td><xsl:value-of select="timestamp"/></td>
    <td> <xsl:value-of select="local-name()"/> </td>
    
    <xsl:choose>
        <xsl:when test="local-name()='message'">
            <td> <xsl:value-of select="level"/> </td>
            <td> <xsl:value-of select="value"/> </td>
        </xsl:when>
        <xsl:otherwise>
            <td/>
        </xsl:otherwise>
    </xsl:choose>
    <xsl:if test="local-name()='send' or local-name()='recv'">
        <td>
        <table border="1" style="margin: 5px; border-collapse: collapse;">
            <tr> <td align="center" colspan="2">
            <b>Data</b>
            </td></tr>
            <tr>
            <td> HEX </td>
            <td> 
                <xsl:choose>
                <xsl:when test="string-length(data/hex) &gt; 20">
                <xsl:call-template name="linebreaklongwords">
                <xsl:with-param name="str" select="data/hex" />
                <xsl:with-param name="len" select="20" />
                </xsl:call-template>
                </xsl:when>
                <xsl:otherwise>
                <xsl:value-of select="data/hex"/>
                </xsl:otherwise>
                </xsl:choose>
            </td>
            </tr>
            <tr>
                <td> ASCII </td>
                <td> 
                    <xsl:choose>
                    <xsl:when test="string-length(data/ascii) &gt; 20">
                    <xsl:call-template name="linebreaklongwords">
                    <xsl:with-param name="str" select="data/ascii" />
                    <xsl:with-param name="len" select="20" />
                    </xsl:call-template>
                    </xsl:when>
                    <xsl:otherwise>
                    <xsl:value-of select="data/ascii"/>
                    </xsl:otherwise>
                    </xsl:choose>
                </td>
            </tr>
        </table>
        <!---          Frames for end-->
        <table border="1" style="margin: 5px; border-collapse: collapse;">
        <tr> <td align="center" colspan="2">
        <b>RAW frames</b>
        </td></tr>
        <xsl:for-each select="frames/*">
            <tr><td>
                <xsl:choose>
                    <xsl:when test="string-length(.) &gt; 20">
                    <xsl:call-template name="linebreaklongwords">
                    <xsl:with-param name="str" select="." />
                    <xsl:with-param name="len" select="20" />
                    </xsl:call-template>
                    </xsl:when>
                    <xsl:otherwise>
                    <xsl:value-of select="."/>
                    </xsl:otherwise>
                </xsl:choose>
            </td></tr>
        </xsl:for-each>
        </table>
        <!--- Table for frames end-->
        <!---   parsed value status -->
        <table border="1" style="margin: 5px; border-collapse: collapse;" bgcolor="#606090">
        <tr> <td align="center" colspan="2">
        <b>
            <xsl:choose>
                <xsl:when test="local-name()='send'"> 
                    <xsl:text> CLA,INS,P1,P2 </xsl:text>
                </xsl:when>
                <xsl:when test="local-name()='recv'"> 
                    <xsl:text> Status </xsl:text>
                </xsl:when>
            </xsl:choose>
        </b>
        </td></tr>
        <tr>
            <td> Data </td>
            <td>  <xsl:value-of select="parsed/value/hex"/> </td>
        </tr>
        <tr>
            <td> Description </td>
            <td>  <xsl:value-of select="parsed/value/ascii"/> </td>
        </tr>
        </table>
        <!---   parsed value status END-->
        <!---   TLV table status -->
        <table border="1" style="margin: 5px; border-collapse: collapse;" bgcolor="#606090">
        <tr> <td align="center" colspan="2"><b> TLV </b></td></tr>
        <tr>
            <td> <b>Position</b> </td>
            <td> <b>Element</b>  </td>
        </tr>
        <xsl:for-each select="parsed/tlv/*">
            <tr>
                <td> <xsl:value-of select="position()"/> </td>
                <td>
                    <xsl:choose>
                        <xsl:when test="local-name()='tag'">
                               <!-- Internal TAG table -->
                                <xsl:for-each select=".">
                                <table border="1" style="margin: 0px; border-collapse: collapse;" bgcolor="#B0B020">
                                    <tr><td colspan="2" align="center"><b>TAG</b></td></tr>
                                    <tr><td> HEX </td><td><xsl:value-of select="value"/></td></tr>
                                    <tr><td> Desc </td><td><xsl:value-of select="desc"/></td></tr>
                                    <tr><td> Data HEX </td><td>
                                           <xsl:choose>
                                           <xsl:when test="string-length(data/hex) &gt; 20">
                                           <xsl:call-template name="linebreaklongwords">
                                           <xsl:with-param name="str" select="data/hex" />
                                           <xsl:with-param name="len" select="20" />
                                           </xsl:call-template>
                                           </xsl:when>
                                           <xsl:otherwise>
                                           <xsl:value-of select="data/hex"/>
                                           </xsl:otherwise>
                                            </xsl:choose>
                                        </td></tr>
                                    <tr><td> Data ASCII </td><td>
                                           <xsl:choose>
                                           <xsl:when test="string-length(data/ascii) &gt; 20">
                                           <xsl:call-template name="linebreaklongwords">
                                           <xsl:with-param name="str" select="data/ascii" />
                                           <xsl:with-param name="len" select="20" />
                                           </xsl:call-template>
                                           </xsl:when>
                                           <xsl:otherwise>
                                           <xsl:value-of select="data/ascii"/>
                                           </xsl:otherwise>
                                            </xsl:choose>

                                        </td></tr>
                                </table>
                                </xsl:for-each>
                                <!-- Internal TAG table - END -->
                        </xsl:when>
                        <xsl:when test="local-name()='template'">
                            <!-- Handle template -->
                            <table border="1" style="margin: 0px; border-collapse: collapse;" bgcolor="#700000">
                                <tr><td colspan="2" align="center"> <b>Template <xsl:value-of select="value"/><br/> (<xsl:value-of select="desc"/>) </b> </td></tr>
                                <!-- Internal TAG table -->
                                <xsl:for-each select="tag">
                                <tr> 
                                <td> <xsl:value-of select="position()"/> </td>
                                <td>
                                <table border="1" style="margin: 0px; border-collapse: collapse;" bgcolor="#B0B020">
                                    <tr><td colspan="2" align="center"><b>TAG</b></td></tr>
                                    <tr><td> HEX </td><td><xsl:value-of select="value"/></td></tr>
                                    <tr><td> Desc </td><td><xsl:value-of select="desc"/></td></tr>
                                    <tr><td> Data HEX </td><td>
                                           <xsl:choose>
                                           <xsl:when test="string-length(data/hex) &gt; 20">
                                           <xsl:call-template name="linebreaklongwords">
                                           <xsl:with-param name="str" select="data/hex" />
                                           <xsl:with-param name="len" select="20" />
                                           </xsl:call-template>
                                           </xsl:when>
                                           <xsl:otherwise>
                                           <xsl:value-of select="data/hex"/>
                                           </xsl:otherwise>
                                            </xsl:choose>
                                        </td></tr>
                                    <tr><td> Data ASCII </td><td>
                                           <xsl:choose>
                                           <xsl:when test="string-length(data/ascii) &gt; 20">
                                           <xsl:call-template name="linebreaklongwords">
                                           <xsl:with-param name="str" select="data/ascii" />
                                           <xsl:with-param name="len" select="20" />
                                           </xsl:call-template>
                                           </xsl:when>
                                           <xsl:otherwise>
                                           <xsl:value-of select="data/ascii"/>
                                           </xsl:otherwise>
                                            </xsl:choose>

                                        </td></tr>
                                </table></td></tr>
                                </xsl:for-each>
                                <!-- Internal TAG table - END -->
                            </table>
                        </xsl:when>
                    </xsl:choose>
                </td>
            </tr>
        </xsl:for-each>
        </table>
        <!---   TLV table status END -->
    </td>
    </xsl:if>
      </tr>
  </xsl:for-each>
  </table>

  </body>
  </html>
</xsl:template>

</xsl:stylesheet> 
