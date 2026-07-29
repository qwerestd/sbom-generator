use crate::analyze::producers::maven::maven_file::{MavenFile, MavenProjectInfo};
use crate::utils::tree_sitter::language::get_tree_sitter_xml;
use std::collections::HashMap;
use std::path::PathBuf;

const TREE_SITTER_PARENT_INFORMATION: &str = r###"
(document
  root: (element
	(STag
	  (Name) @project
	)
	(content
	  (element
		(STag
		  (Name) @parent
		)
		(content
		  (element
		  (STag
			(Name) @key
		  )
		  (content) @value
		  (ETag)
		  )
		)+
	  )
	)
	(#eq? @project "project")
	(#eq? @parent "parent")
	(#any-of? @key "relativePath" "groupId" "artifactId" "version")
  )
)
"###;

const TREE_SITTER_PROJECT_METADATA: &str = r###"
(document
  root: (element
	(STag
	  (Name) @project
	)

    (content
      (element
      (STag
        (Name) @key
      )
      (content) @value
      (ETag)
      )
    )+

	(#eq? @project "project")
	(#any-of? @key "groupId" "artifactId" "version")
  )
)

(element
   (STag
      (Name) @project
   )
   (content
      (element
         (STag
            (Name) @version
         )
         (content) @value
      )
   )
   (#eq? @project "project")
   (#eq? @version "version")
)
"###;

const TREE_SITTER_PROJECT_PROPERTIES: &str = r###"
(element
   (STag
      (Name) @project
   )
   (content
      (element
         (STag
            (Name) @properties
         )
         (content
            (element
               (STag
                  (Name) @key
               )
               (content) @value
            )

         )
      )
   )
   (#eq? @project "project")
   (#eq? @properties "properties")
)
"###;

const TREE_SITTER_QUERY_DEPENDENCY_MANAGEMENT: &str = r###"
(element
   (STag
      (Name)@project
   )
   (content
        (element
            (STag
                (Name)@dependencyManagement
            )
            (content
                (element
                    (STag
                        (Name) @dependencies
                    )
                    (content
                        (element
                           (STag
                              (Name)@name
                           )
                           (content
                             (
                                 (element
                                    (STag
                                       (Name)@tag
                                    )
                                    (content)@value
                                 )
                                 (CharData)
                             )+
                           )
                           (#eq? @name "dependency")
                        )@element
                    )
                    (#eq? @dependencies "dependencies")
                )
            )
        )
   )
   (#eq? @dependencyManagement "dependencyManagement")
   (#eq? @project "project")
)
"###;

const TREE_SITTER_QUERY_DEPENDENCIES: &str = r###"
(element
   (STag
      (Name)@project
   )
   (content
        (element
            (STag
                (Name) @dependencies
            )
            (content
                (element
                   (STag
                      (Name)@name
                   )
                   (content
                     (
                         (element
                            (STag
                               (Name)@tag
                            )
                            (content)@value
                         )
                         (CharData)
                     )+
                   )
                   (#eq? @name "dependency")
                )@element
            )
            (#eq? @dependencies "dependencies")
        )
   )
   (#eq? @project "project")
)
"###;

/// Context everything you need to write your SBOM. This includes all the tree-sitter
/// queries but also all the files that were parsed. This way, if we need to resolve
/// variables post-processing, we can use them using this structure.
pub struct MavenProducerContext {
    pub base_path: PathBuf,
    #[allow(dead_code)]
    pub query_project_metadata: tree_sitter::Query,
    pub query_project_properties: tree_sitter::Query,
    #[allow(dead_code)]
    pub query_parent_information: tree_sitter::Query,
    pub query_dependencies: tree_sitter::Query,
    pub query_dependency_management: tree_sitter::Query,
    pub language: tree_sitter::Language,
    /// hold a copy of the maven file data indexed by path for easy retrieval and indexing
    /// when looking for a parent.
    maven_files_by_path: HashMap<PathBuf, MavenFile>,
    /// hold a copy o maven file by project information. It's used if we do not have the
    /// path information.
    maven_files_by_project_info: HashMap<MavenProjectInfo, MavenFile>,
    /// Copy of all maven files that have been found.
    maven_files: Vec<MavenFile>,
}

impl Default for MavenProducerContext {
    fn default() -> Self {
        Self::new(PathBuf::default())
    }
}

impl MavenProducerContext {
    pub fn add_maven_file(&mut self, maven_file: &MavenFile) {
        let relative_path = maven_file
            .path
            .strip_prefix(&self.base_path)
            .unwrap_or(&maven_file.path)
            .to_path_buf();

        self.maven_files_by_path
            .insert(relative_path, maven_file.clone());
        self.maven_files_by_project_info
            .insert(maven_file.project_info.clone(), maven_file.clone());
        self.maven_files.push(maven_file.clone());
    }

    pub fn get_maven_file_by_project_info(
        &self,
        project_info: &MavenProjectInfo,
    ) -> Option<&MavenFile> {
        self.maven_files_by_project_info.get(project_info)
    }

    pub fn get_maven_file_by_path(&self, path: &PathBuf) -> Option<&MavenFile> {
        self.maven_files_by_path.get(path)
    }

    pub fn get_all_files(&self) -> &Vec<MavenFile> {
        &self.maven_files
    }

    pub fn new(bp: PathBuf) -> Self {
        let xml_language = get_tree_sitter_xml();

        MavenProducerContext {
            base_path: bp,
            query_project_metadata: tree_sitter::Query::new(
                &xml_language,
                TREE_SITTER_PROJECT_METADATA,
            )
            .expect("got query variables"),
            query_dependencies: tree_sitter::Query::new(
                &xml_language,
                TREE_SITTER_QUERY_DEPENDENCIES,
            )
            .expect("got query dependencies"),
            query_dependency_management: tree_sitter::Query::new(
                &xml_language,
                TREE_SITTER_QUERY_DEPENDENCY_MANAGEMENT,
            )
            .expect("got query dependency management"),
            query_project_properties: tree_sitter::Query::new(
                &xml_language,
                TREE_SITTER_PROJECT_PROPERTIES,
            )
            .expect("got query project properties"),
            query_parent_information: tree_sitter::Query::new(
                &xml_language,
                TREE_SITTER_PARENT_INFORMATION,
            )
            .expect("got query parent info"),
            language: xml_language,
            maven_files_by_path: HashMap::new(),
            maven_files_by_project_info: HashMap::new(),
            maven_files: vec![],
        }
    }
}
