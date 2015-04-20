using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit;
using NUnit.Framework;
using XssValidator.Tests.TestClass;
using XssValidator.Validate;

namespace XssValidator.Tests
{
    [TestFixture]
    public class XssSequentialValidationTest
    {
        private static TestComplexClass1 objtestComplexClass1;
        
        [Test]
        public void test_input_of_type_complexclass_for_xss_validation()
        {
            var objTestComplexClass21 = new TestComplexClass2 { DeptId = 1, DeptName = "Sample<script>" };
            var objTestComplexClass22 = new TestComplexClass2 { DeptId = 1, DeptName = "Delete from Employee" };
            var objtestComplexClass1 = new TestComplexClass1
            {
                Age = 1,
                Name = "Drop Table Table1",
                Dept = new List<TestComplexClass2> { objTestComplexClass21, objTestComplexClass22 }
            };
            var result= Validator.ValidateForXssScriptSequential<TestComplexClass1>(objtestComplexClass1);
            Assert.AreEqual(result, false);
        }

        [Test]
        public void test_input_of_type_string_for_xss_validation()
        {
            var result = Validator.ValidateForXssScriptSequential("hello");
            Assert.AreEqual(result, true);
        }

        [Test]
        public void test_input_of_type_string_for_xss_validation_with_xss_content()
        {
            var result = Validator.ValidateForXssScriptSequential("<alert>Hi!!!</alert>");
            Assert.AreEqual(result, false);
        }

        [Test]
        public void test_input_of_type_complexclass_for_xss_validation_without_injection()
        {
            var objTestComplexClass21 = new TestComplexClass2 { DeptId = 1, DeptName = "Sample" };
            var objTestComplexClass22 = new TestComplexClass2 { DeptId = 1, DeptName = "Employee" };
            var objtestComplexClass1 = new TestComplexClass1
            {
                Age = 1,
                Name = "physics",
                Dept = new List<TestComplexClass2> { objTestComplexClass21, objTestComplexClass22 }
            };
            var result = Validator.ValidateForXssScriptSequential<TestComplexClass1>(objtestComplexClass1);
            Assert.AreEqual(result, true);
        }

        [Test]
        public void test_input_of_type_complexclass_for_xss_validation_with_injection()
        {
            var objTestComplexClass21 = new TestComplexClass2 { DeptId = 1, DeptName = "Delete" };
            var objTestComplexClass22 = new TestComplexClass2 { DeptId = 1, DeptName = "Employee" };
            var objtestComplexClass1 = new TestComplexClass1
            {
                Age = 1,
                Name = "Sample",
                Dept = new List<TestComplexClass2> { objTestComplexClass21, objTestComplexClass22 }
            };
            var result = Validator.ValidateForXssScriptSequential<TestComplexClass2>(objtestComplexClass1.Dept.FirstOrDefault());
            Assert.AreEqual(result, false);
        }


        [Test]
        public void test_input_of_type_complexclass_for_xss_validation_without_injection_parallel()
        {
            var objTestComplexClass21 = new TestComplexClass2 { DeptId = 1, DeptName = "Sample" };
            var objTestComplexClass22 = new TestComplexClass2 { DeptId = 1, DeptName = "Employee" };
            var objtestComplexClass1 = new TestComplexClass1
            {
                Age = 1,
                Name = "physics",
                Dept = new List<TestComplexClass2> { objTestComplexClass21, objTestComplexClass22 }
            };
            var result = Validator.ValidateForXssScriptParallel<TestComplexClass1>(objtestComplexClass1);
            Assert.AreEqual(result, true);
        }

        
    }
}
