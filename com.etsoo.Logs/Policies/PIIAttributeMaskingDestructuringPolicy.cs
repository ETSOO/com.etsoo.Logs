using com.etsoo.Utils.Serialization;
using Serilog.Core;
using Serilog.Events;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

namespace com.etsoo.Logs.Policies
{
    /// <summary>
    /// PII (Personally Identifiable Information) destructuring policy, support PIIAttribute and JsonIgnoreAttribute
    /// PII（个人身份信息）解构政策，支持 PIIAttribute 和 JsonIgnoreAttribute
    /// </summary>
    public class PIIAttributeMaskingDestructuringPolicy : IDestructuringPolicy
    {
        public bool TryDestructure(object value, ILogEventPropertyValueFactory propertyValueFactory, [NotNullWhen(true)] out LogEventPropertyValue? result)
        {
            var type = value.GetType();
            if (type.GetCustomAttribute<PIIAttribute>(true) != null)
            {
                result = new ScalarValue("***");
                return true;
            }

            result = null;
            return false;
        }
    }
}
