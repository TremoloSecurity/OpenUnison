/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.openunison.util.config;

import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.ArrayList;
import java.util.Comparator;

public class OpenUnisonConfigLoader {

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenUnisonConfigLoader.class.getName());

    public static String generateOpenUnisonConfig(String srcPath) throws Exception {
        StringBuffer b = new StringBuffer();
        b.setLength(0);
        String line = null;

        BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(srcPath)));

        while ((line = in.readLine()) != null) {
            b.append(line).append('\n');
        }

        String cfg = b.toString();
        if (logger.isDebugEnabled()) {
            logger.debug("---------------");
            logger.debug("Before environment variables : '" + srcPath + "'");
            logger.debug(cfg);
            logger.debug("---------------");
        }

        b.setLength(0);
        includeFiles(b,cfg,new File(srcPath).getParent());
        if (b.toString().trim().length() > 0) {
            logger.info("No config from include files, using original");
            cfg = b.toString();
        }

        b.setLength(0);
        integrateIncludes(b, cfg);

        if (b.toString().trim().length() == 0) {
            logger.info("No config from include env, using original");
            b.append(cfg);
        }

        int begin,end;


        begin = 0;
        end = 0;



        if (logger.isDebugEnabled()) {
            logger.debug("---------------");
            logger.debug("After environment variables : '" + srcPath + "'");
            logger.debug(b.toString());
            logger.debug("---------------");
        }

        return b.toString();


    }

    private static void integrateIncludes(StringBuffer newConfig, String originalConfig) {
        int begin,end;


        begin = 0;
        end = 0;

        String finalCfg = null;

        begin = originalConfig.indexOf("#[");
        while (begin > 0) {
            if (end == 0) {
                newConfig.append(originalConfig.substring(0,begin));
            } else {
                newConfig.append(originalConfig.substring(end,begin));
            }

            end = originalConfig.indexOf(']',begin + 2);

            String envVarName = originalConfig.substring(begin + 2,end);
            String defaultValue = "";
            if (envVarName.contains(":")) {
            	defaultValue = envVarName.substring(envVarName.indexOf(":") + 1);
            	envVarName = envVarName.substring(0, envVarName.indexOf(":"));
            }
            
            String value = System.getenv(envVarName);

            if (value == null) {
                value = System.getProperty(envVarName);
            }

            if (value == null) {
                value = defaultValue;
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Environment Variable '" + envVarName + "'='" + value + "'");
            }

            newConfig.append(value);

            begin = originalConfig.indexOf("#[",end + 1);
            end++;

        }

        if (end != 0) {
            newConfig.append(originalConfig.substring(end));
        }

    }

    private static void includeFiles(StringBuffer newConfig, String originalConfig,String basePath) throws Exception {
        int begin,end;


        begin = 0;
        end = 0;

        String finalCfg = null;

        begin = originalConfig.indexOf("@[");
        while (begin > 0) {
            if (end == 0) {
                newConfig.append(originalConfig.substring(0,begin));
            } else {
                newConfig.append(originalConfig.substring(end,begin));
            }

            end = originalConfig.indexOf(']',begin + 2);

            String includeDirective = originalConfig.substring(begin + 2,end);

            String includeType = includeDirective.substring(0,includeDirective.indexOf(':'));
            String includePath = includeDirective.substring(includeDirective.indexOf(':') + 1);
            String includeFilePath = basePath + File.separator + includePath;

            if (includeType.equalsIgnoreCase("file")) {
                importFile(newConfig, includeFilePath);


            } else if (includeType.equalsIgnoreCase("dir")) {
                File dir = new File(includeFilePath);
                if (! dir.isDirectory()) {
                    throw new Exception("Not a directory : '" + dir.getAbsolutePath() + "'");
                }

                ArrayList<File> filesToImport = new ArrayList<File>();
                for (File f : dir.listFiles()) {
                    filesToImport.add(f);
                }

                filesToImport.sort(new Comparator<File>() {
                    @Override
                    public int compare(File file, File t1) {
                        return file.getName().compareTo(t1.getName());
                    }
                });

                for (File f : filesToImport) {
                    importFile(newConfig,f.getAbsolutePath());
                }
            } else {
                throw new Exception("Could not determine include type : '" + includeType + "'");
            }



            begin = originalConfig.indexOf("@[",end + 1);
            end++;

        }

        if (end != 0) {
            newConfig.append(originalConfig.substring(end));
        }

    }

    private static void importFile(StringBuffer newConfig, String includeFilePath) throws IOException {
        File toInclude = new File(includeFilePath);
        if (toInclude.exists()) {
            StringBuffer tmp = new StringBuffer();
            BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(toInclude)));
            String line = null;
            while ((line = in.readLine()) != null) {
                tmp.append(line).append('\n');
            }
            newConfig.append(tmp);
        }
    }
}
