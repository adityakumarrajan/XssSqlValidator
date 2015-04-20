using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using Microsoft.Security.Application;
using System.Configuration;

namespace XssValidator.Validate
{
    public static class Validator
    {
        private static readonly string DmlCmd = "DmlCmd";
        private static readonly string strTypeName = "String";
        private static readonly string strFullName = "System.";

        public static bool ValidateForXssScriptSequential<T>(T input)
        {
            if (IsTypeSystemString<T>(input))
            {
                return ValidateInput(Convert.ToString(input));
            }

            var propInfo = input.GetType().GetProperties();
            foreach (var prop in propInfo)
            {
                if ((prop.PropertyType == typeof(string)))
                {
                    var propValue = Convert.ToString(prop.GetValue(input, null));
                    if (!ValidateInput(propValue))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static bool ValidateForXssScriptParallel<T>(T input)
        {
            var finalResult = true;
            if (IsTypeSystemString<T>(input))
            {
                finalResult = ValidateInput(Convert.ToString(input));
                return finalResult;
            }

            var propInfo = input.GetType().GetProperties();
            Parallel.ForEach<PropertyInfo>(propInfo, (prop,state) =>
            {
                if (prop.PropertyType.Name.Contains(strTypeName))
                {
                    var propValue = Convert.ToString(prop.GetValue(input, null));
                    if (!ValidateInput(propValue))
                    {
                        finalResult=false;
                        state.Break();
                    }
                }
            });
            return finalResult;
        }

        #region Core Validation Logic
        
        /// <summary>
        /// This Methods check if Type T is System.String
        /// </summary>
        /// <typeparam name="T">Type of Variable</typeparam>
        /// <param name="input">input variable</param>
        /// <returns></returns>
        private static bool IsTypeSystemString<T>(T input)
        {
            var result= input.GetType().FullName.Contains(strTypeName);
            return result;
        }

        /// <summary>
        /// This method validates an input for CSS and SQL Injection.
        /// </summary>
        /// <param name="input">Enter value that has to be validated for CSS or SQL attack.</param>
        /// <returns></returns>
        private static bool ValidateInput(string input)
        {
            if (!ValidateCss(input) || !ValidateSql(input))
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// This methods used Sanitizer Method provided by "HtmlSanitizationLibrary" for checking if input contains any CSS input.
        /// If there is not CSS Attack then this method returns true else false.
        /// </summary>
        /// <param name="input">Enter value that has to be validated for CSS Attack.</param>
        /// <returns></returns>
        private static bool ValidateCss(string input)
        {
            var result = Sanitizer.GetSafeHtmlFragment(input).Equals(input);
            return result;
        }

        /// <summary>
        /// If string input contains any SQL Injection syntax or DML Elements, this method returns false else true.
        /// </summary>
        /// <param name="input">Enter value that has to be validated for sql Injection or DML keywords.</param>
        /// <returns></returns>
        private static bool ValidateSql(string input)
        {
            var arrDmlCmd = GetValueFromConfiguration(DmlCmd).Replace(" ", "").Split(',');
            var arrinput = input.ToLower().Split(' ');
            if (arrinput.Intersect(arrDmlCmd).Any())
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Returns value from the app.config for the given string appKey
        /// </summary>
        /// <param name="appKey">Enter Key whose value has to be fetched from app.config</param>
        /// <returns></returns>
        private static string GetValueFromConfiguration(string appKey)
        {
            var appValue = ConfigurationManager.AppSettings[appKey].ToLower();
            return appValue;
        }

        #endregion
    }
}
