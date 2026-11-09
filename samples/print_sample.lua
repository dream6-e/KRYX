-- print_sample.lua
-- Simple print sample for Prometheus obfuscation demo
local name = "KRYX"
local numbers = {1, 2, 3, 4, 5}
local sum = 0

for _, n in ipairs(numbers) do
    sum = sum + n
end

print("Hello, " .. name .. "!")
print("Sum of 1..5 is: " .. sum)
print(string.format("Pi is roughly %.2f", math.pi))
