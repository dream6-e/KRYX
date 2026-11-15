// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
pub struct GcRef<T>(std::marker::PhantomData<T>);
pub trait Trace {}
pub struct Closure;
pub struct LuaThread;
pub struct LuaString;
pub struct Table;
