using com.etsoo.Logs.Attributes;
using Serilog.Core;
using Serilog.Events;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text.Json.Serialization;

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
            if (type.GetCustomAttribute<PIIAttribute>() != null || type.GetCustomAttribute<JsonIgnoreAttribute>() != null)
            {
                result = new ScalarValue("***");
                return true;
            }

            result = null;
            return false;
        }
    }
}
