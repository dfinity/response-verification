use ic_http_certification::{HttpRequest, HttpResponse};
use matchit::Params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TodoItem {
    pub id: u32,
    pub title: String,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub enum ApiResponse<'a, T = ()> {
    #[serde(rename = "ok")]
    Ok { data: &'a T },
    #[serde(rename = "err")]
    Err { code: u16, message: String },
}

impl<'a, T: Serialize> ApiResponse<'a, T> {
    pub fn ok(data: &'a T) -> ApiResponse<T> {
        Self::Ok { data }
    }

    pub fn not_found() -> Self {
        Self::err(404, "Not found".to_string())
    }

    pub fn not_allowed() -> Self {
        Self::err(405, "Method not allowed".to_string())
    }

    fn err(code: u16, message: String) -> Self {
        Self::Err { code, message }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize value")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTodoItemRequest {
    pub title: String,
}

pub type CreateTodoItemResponse<'a> = ApiResponse<'a, TodoItem>;

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateTodoItemRequest {
    pub title: Option<String>,
    pub completed: Option<bool>,
}

pub type UpdateTodoItemResponse<'a> = ApiResponse<'a, ()>;

pub type DeleteTodoItemResponse<'a> = ApiResponse<'a, ()>;

pub type ListTodosResponse<'a> = ApiResponse<'a, Vec<TodoItem>>;

pub type ErrorResponse<'a> = ApiResponse<'a, ()>;

pub type RouteHandler = for<'a> fn(&'a HttpRequest, &'a Params) -> HttpResponse;
