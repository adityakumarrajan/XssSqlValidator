using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XssValidator.Tests.TestClass
{
    public class TestComplexClass1
    {
        public string Name { get; set; }
        public int Age { get; set; }
        public List<TestComplexClass2> Dept { get; set; }
    }

}
