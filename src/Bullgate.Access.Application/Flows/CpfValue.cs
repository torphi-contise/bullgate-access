using System.Globalization;

namespace Bullgate.Access.Application.Flows;

/// <summary>Normalizes and validates Brazilian CPF values and ISO birth dates.</summary>
internal static class CpfValue
{
    /// <summary>Accepts eleven digits or the canonical dotted CPF presentation.</summary>
    public static bool TryNormalize(string? value, out string normalized)
    {
        var candidate = value?.Trim() ?? string.Empty;
        if (candidate.Length == 14)
        {
            if (candidate[3] != '.' || candidate[7] != '.' || candidate[11] != '-')
            {
                normalized = string.Empty;
                return false;
            }

            candidate = string.Concat(
                candidate.AsSpan(0, 3),
                candidate.AsSpan(4, 3),
                candidate.AsSpan(8, 3),
                candidate.AsSpan(12, 2));
        }

        if (candidate.Length != 11 || candidate.Any(character => !char.IsAsciiDigit(character)))
        {
            normalized = string.Empty;
            return false;
        }

        if (candidate.All(character => character == candidate[0])
            || CheckDigit(candidate, 9) != candidate[9] - '0'
            || CheckDigit(candidate, 10) != candidate[10] - '0')
        {
            normalized = string.Empty;
            return false;
        }

        normalized = candidate;
        return true;
    }

    /// <summary>Accepts an ISO calendar date that is not later than the supplied day.</summary>
    public static bool TryParseBirthDate(
        string? value,
        DateOnly currentDate,
        out DateOnly birthDate)
    {
        if (!DateOnly.TryParseExact(
                value?.Trim(),
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out birthDate)
            || birthDate > currentDate)
        {
            birthDate = default;
            return false;
        }

        return true;
    }

    private static int CheckDigit(string value, int length)
    {
        var sum = 0;
        for (var index = 0; index < length; index++)
        {
            sum += (value[index] - '0') * (length + 1 - index);
        }

        var remainder = sum % 11;
        return remainder < 2 ? 0 : 11 - remainder;
    }
}
