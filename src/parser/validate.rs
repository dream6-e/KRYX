// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{error_at, Result};
use crate::ast::{Kind, Node};
use std::collections::{HashMap, HashSet};

/// Validate contextual rules without recursion, including shadowing and closures.
pub(super) fn validate(source: &[u8], root: &Node) -> Result<()> {
    validate_exports(source, root)?;
    validate_constants(source, root)
}

fn validate_exports(source: &[u8], root: &Node) -> Result<()> {
    let mut todo = vec![(root, 0usize, 0usize)];
    let mut exported = HashSet::<&[u8]>::new();
    let mut first_export = None;
    let mut module_return = None;
    while let Some((node, blocks, functions)) = todo.pop() {
        let blocks = blocks + usize::from(node.kind == Kind::Block);
        let functions = functions + usize::from(node.kind == Kind::Function);
        if node.kind == Kind::Return && functions == 0 {
            module_return = Some(node.span.start);
        }
        if node.kind == Kind::Export {
            if functions != 0 || blocks != 1 {
                return Err(error_at(
                    source,
                    node.span.start,
                    "值导出只能用于模块顶层".into(),
                ));
            }
            first_export = Some(node.span.start);
            let declaration = &node.children[0];
            let mut names: Vec<&Node> = vec![];
            match declaration.kind {
                Kind::Local | Kind::Const => {
                    names.extend(
                        declaration.children[0]
                            .children
                            .iter()
                            .map(|binding| &binding.children[0]),
                    );
                }
                Kind::FunctionStatement => {
                    let name = &declaration.children[0];
                    if name.kind != Kind::Name {
                        return Err(error_at(
                            source,
                            name.span.start,
                            "导出函数必须是简单名称".into(),
                        ));
                    }
                    names.push(name);
                }
                _ => {
                    return Err(error_at(
                        source,
                        declaration.span.start,
                        "此声明不能被导出".into(),
                    ))
                }
            }
            for name in names {
                if !exported.insert(&source[name.span.clone()]) {
                    return Err(error_at(source, name.span.start, "重复的导出名称".into()));
                }
            }
        }
        todo.extend(
            node.children
                .iter()
                .rev()
                .map(|child| (child, blocks, functions)),
        );
    }
    if let (Some(_), Some(pos)) = (first_export, module_return) {
        return Err(error_at(source, pos, "值导出不能与模块返回同时使用".into()));
    }
    Ok(())
}

enum Task<'a> {
    Visit(&'a Node),
    Function(&'a Node, bool),
    Push,
    Pop,
    Declare(&'a Node, bool),
    DeclareSelf,
    BeginTypeFunction,
    EndTypeFunction,
    CheckTarget(&'a Node),
}

fn validate_constants(source: &[u8], root: &Node) -> Result<()> {
    let mut scopes: Vec<HashMap<Vec<u8>, bool>> = Vec::new();
    let mut todo = vec![Task::Visit(root)];
    let mut type_boundaries: Vec<usize> = Vec::new();
    while let Some(task) = todo.pop() {
        match task {
            Task::Push => scopes.push(HashMap::new()),
            Task::Pop => {
                scopes.pop();
            }
            Task::Declare(name, constant) => {
                scopes
                    .last_mut()
                    .unwrap()
                    .insert(source[name.span.clone()].to_vec(), constant);
            }
            Task::BeginTypeFunction => type_boundaries.push(scopes.len()),
            Task::EndTypeFunction => {
                type_boundaries.pop();
            }
            Task::DeclareSelf => {
                scopes.last_mut().unwrap().insert(b"self".to_vec(), false);
            }
            Task::CheckTarget(target) => {
                if target.kind == Kind::Name {
                    let name = &source[target.span.clone()];
                    if scopes.iter().rev().find_map(|s| s.get(name)).copied() == Some(true) {
                        return Err(error_at(
                            source,
                            target.span.start,
                            "常量不能被重新赋值".into(),
                        ));
                    }
                }
            }
            Task::Function(node, method) => {
                todo.push(Task::Pop);
                if let Some(body) = node.children.iter().find(|child| child.kind == Kind::Block) {
                    todo.push(Task::Visit(body));
                }
                if let Some(params) = node
                    .children
                    .iter()
                    .find(|child| child.kind == Kind::Parameters)
                {
                    for param in params.children.iter().rev() {
                        if param.children[0].kind == Kind::Name {
                            todo.push(Task::Declare(&param.children[0], false));
                        }
                    }
                }
                if method {
                    todo.push(Task::DeclareSelf);
                }
                for child in node.children.iter().rev() {
                    if child.kind != Kind::Block && child.kind != Kind::Parameters {
                        todo.push(Task::Visit(child));
                    }
                    if child.kind == Kind::Parameters {
                        for param in child.children.iter().rev() {
                            for annotation in param.children.iter().skip(1).rev() {
                                todo.push(Task::Visit(annotation));
                            }
                        }
                    }
                }
                todo.push(Task::Push);
            }
            Task::Visit(node) => match node.kind {
                Kind::Name => {
                    if let Some(&boundary) = type_boundaries.last() {
                        let name = &source[node.span.clone()];
                        if let Some((scope, _)) = scopes
                            .iter()
                            .enumerate()
                            .rev()
                            .find(|(_, scope)| scope.contains_key(name))
                        {
                            if scope < boundary {
                                return Err(error_at(
                                    source,
                                    node.span.start,
                                    "类型函数不能引用外部局部变量".into(),
                                ));
                            }
                        }
                    }
                }
                Kind::TypeFunction | Kind::ExportTypeFunction => {
                    todo.push(Task::EndTypeFunction);
                    todo.push(Task::Function(&node.children[1], false));
                    todo.push(Task::BeginTypeFunction);
                }
                Kind::Field | Kind::MethodField => todo.push(Task::Visit(&node.children[0])),
                Kind::MethodCall => {
                    for child in node.children.iter().skip(2).rev() {
                        todo.push(Task::Visit(child));
                    }
                    todo.push(Task::Visit(&node.children[0]));
                }
                Kind::TableRecord => todo.push(Task::Visit(&node.children[1])),
                Kind::TypeAlias
                | Kind::ExportTypeAlias
                | Kind::Type
                | Kind::TypeTuple
                | Kind::TypePack
                | Kind::TypeFunctionExpression
                | Kind::TypeBinary(_)
                | Kind::TypeOptional
                | Kind::TypeArguments
                | Kind::GenericParameters
                | Kind::TypeField
                | Kind::Parameter => {
                    for child in node.children.iter().rev() {
                        if child.kind != Kind::Name {
                            todo.push(Task::Visit(child));
                        }
                    }
                }
                Kind::Block => {
                    todo.push(Task::Pop);
                    for child in node.children.iter().rev() {
                        todo.push(Task::Visit(child));
                    }
                    todo.push(Task::Push);
                }
                Kind::Local | Kind::Const => {
                    let constant = node.kind == Kind::Const;
                    let bindings = &node.children[0];
                    for binding in bindings.children.iter().rev() {
                        todo.push(Task::Declare(&binding.children[0], constant));
                    }
                    for child in node.children.iter().skip(1).rev() {
                        todo.push(Task::Visit(child));
                    }
                    for binding in bindings.children.iter().rev() {
                        for annotation in binding.children.iter().skip(1).rev() {
                            todo.push(Task::Visit(annotation));
                        }
                    }
                }
                Kind::LocalFunction | Kind::ConstFunction => {
                    todo.push(Task::Function(&node.children[1], false));
                    todo.push(Task::Declare(
                        &node.children[0],
                        node.kind == Kind::ConstFunction,
                    ));
                }
                Kind::Function => todo.push(Task::Function(node, false)),
                Kind::FunctionStatement => {
                    let target = &node.children[0];
                    todo.push(Task::Function(
                        &node.children[1],
                        target.kind == Kind::MethodField,
                    ));
                    todo.push(Task::Visit(target));
                    todo.push(Task::CheckTarget(target));
                }
                Kind::Export if node.children[0].kind == Kind::FunctionStatement => {
                    let decl = &node.children[0];
                    todo.push(Task::Function(&decl.children[1], false));
                    todo.push(Task::Declare(&decl.children[0], true));
                }
                Kind::Assignment | Kind::CompoundAssignment(_) => {
                    let targets: Vec<&Node> = if node.kind == Kind::Assignment {
                        node.children[0].children.iter().collect()
                    } else {
                        vec![&node.children[0]]
                    };
                    for target in targets.iter().rev() {
                        todo.push(Task::CheckTarget(target));
                    }
                    for child in node.children.iter().rev() {
                        todo.push(Task::Visit(child));
                    }
                }
                Kind::ForNumeric => {
                    let binding = &node.children[0];
                    todo.push(Task::Pop);
                    todo.push(Task::Visit(node.children.last().unwrap()));
                    todo.push(Task::Declare(&binding.children[0], false));
                    todo.push(Task::Push);
                    for value in node.children[1..node.children.len() - 1].iter().rev() {
                        todo.push(Task::Visit(value));
                    }
                    for annotation in binding.children.iter().skip(1).rev() {
                        todo.push(Task::Visit(annotation));
                    }
                }
                Kind::ForGeneric => {
                    let bindings = &node.children[0];
                    todo.push(Task::Pop);
                    todo.push(Task::Visit(node.children.last().unwrap()));
                    for binding in bindings.children.iter().rev() {
                        todo.push(Task::Declare(&binding.children[0], false));
                    }
                    todo.push(Task::Push);
                    todo.push(Task::Visit(&node.children[1]));
                    for binding in bindings.children.iter().rev() {
                        for annotation in binding.children.iter().skip(1).rev() {
                            todo.push(Task::Visit(annotation));
                        }
                    }
                }
                Kind::Repeat => {
                    todo.push(Task::Pop);
                    todo.push(Task::Visit(&node.children[1]));
                    for stmt in node.children[0].children.iter().rev() {
                        todo.push(Task::Visit(stmt));
                    }
                    todo.push(Task::Push);
                }
                Kind::While
                    if matches!(
                        node.children[0].kind,
                        Kind::ConditionalBinding | Kind::ConditionalConstBinding
                    ) =>
                {
                    schedule_condition(&mut todo, &node.children[0], &node.children[1])
                }
                Kind::Branch => schedule_condition(&mut todo, &node.children[0], &node.children[1]),
                Kind::IfExpression => {
                    let children = &node.children;
                    todo.push(Task::Visit(children.last().unwrap()));
                    for pair in children[..children.len() - 1].chunks_exact(2).rev() {
                        schedule_condition(&mut todo, &pair[0], &pair[1]);
                    }
                }
                _ => {
                    for child in node.children.iter().rev() {
                        todo.push(Task::Visit(child));
                    }
                }
            },
        }
    }
    Ok(())
}

fn schedule_condition<'a>(todo: &mut Vec<Task<'a>>, condition: &'a Node, consequent: &'a Node) {
    if matches!(
        condition.kind,
        Kind::ConditionalBinding | Kind::ConditionalConstBinding
    ) {
        todo.push(Task::Pop);
        todo.push(Task::Visit(consequent));
        todo.push(Task::Declare(
            &condition.children[0].children[0],
            condition.kind == Kind::ConditionalConstBinding,
        ));
        todo.push(Task::Push);
        todo.push(Task::Visit(&condition.children[1]));
        for annotation in condition.children[0].children.iter().skip(1).rev() {
            todo.push(Task::Visit(annotation));
        }
    } else {
        todo.push(Task::Visit(consequent));
        todo.push(Task::Visit(condition));
    }
}
